// login.go 面板内嵌的国内/国际 OAuth 设备授权流程。
//
//	POST /panel/api/login/start → 拿 state+authUrl，state 存进程内（不再落 /tmp，
//	  原方案在 Windows 上不可用），返回授权 URL；
//	GET  /panel/api/login/poll   → 面板前端每 3s 轮询本接口；未完成返回 done=false，
//	  完成后取 uid/nickname、凭证落盘 auths/workbuddy-<uid>.json、热加载进池
//	  （pool.Add + Revive），并顺带签到 + 余额刷新 —— 免重启加载新账号。
//
// 无 PKCE（workbuddy 设备流由服务端签发 state），请求头与上游端点与 cmd/login 保持一致。
package panel

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

type loginSession struct {
	Created time.Time
	Site    auth.Site
	State   string
	Busy    bool
	Result  map[string]any
}

// loginHTTP 设备授权专用 client：短超时、无 cookie（每请求携带 state，无会话态）。
var loginHTTP = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// validUID 校验上游返回的 uid 是否可安全用于拼文件名。
// 只放行字母、数字、下划线、连字符（腾讯侧 uid 实测为 UUID 形态），
// 长度上限 64 兜底异常超长串；拒绝 . / \ 等路径字符与空串。
func validUID(uid string) bool {
	if uid == "" || len(uid) > 64 {
		return false
	}
	for _, c := range uid {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// apiEnvelope 与 upstream 同形：{code,msg,data}，code!=0 视为业务错误。
type apiEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// doJSON 发一次 JSON 请求并解信封。
func loginJSON(site auth.Site, method, path, bearer, domain string, body io.Reader) (json.RawMessage, int, error) {
	base := "https://" + site.Host
	if !site.International && !site.WorkBuddy {
		base = "https://copilot.tencent.com"
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, 0, err
	}
	(&upstream.Client{}).CommonHeaders(req, &auth.Auth{Domain: site.Host})
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if domain != "" {
		req.Header.Set("X-Domain", domain)
	}
	resp, err := loginHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("http_error: upstream %d", resp.StatusCode)
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("parse failed: %w", err)
	}
	if env.Code != 0 {
		return nil, resp.StatusCode, fmt.Errorf("code=%d msg=%s", env.Code, env.Msg)
	}
	return env.Data, resp.StatusCode, nil
}

// loginStart 发起设备授权：POST auth/state 拿授权 URL。
func (p *Panel) loginStart(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Site    string `json:"site"`
		Product string `json:"product"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil && err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid login options")
		return
	}
	if input.Site == "" {
		input.Site = "cn"
	}
	if input.Product == "" {
		input.Product = "cli"
		if input.Site == "intl" {
			input.Product = "workbuddy"
		}
	}
	host := map[string]string{
		"cn:cli": "www.codebuddy.cn", "cn:workbuddy": "www.workbuddy.cn",
		"intl:cli": "www.codebuddy.ai", "intl:workbuddy": "www.workbuddy.ai",
	}[input.Site+":"+input.Product]
	if host == "" {
		writeErr(w, http.StatusBadRequest, "invalid login site or product")
		return
	}
	site, _ := auth.ResolveSite(&auth.Auth{Domain: host})
	platform := "CLI"
	if site.WorkBuddy {
		platform = "workbuddy"
	}
	data, status, err := loginJSON(site, http.MethodPost,
		"/v2/plugin/auth/state?platform="+platform, "", "", bytes.NewReader([]byte("{}")))
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("auth state (upstream %d): %v", status, err))
		return
	}
	var st struct {
		State   string `json:"state"`
		AuthURL string `json:"authUrl"`
	}
	if err := json.Unmarshal(data, &st); err != nil || st.State == "" || st.AuthURL == "" {
		writeErr(w, http.StatusBadGateway, "auth state: missing state or authUrl")
		return
	}
	link, err := url.Parse(st.AuthURL)
	if err != nil || link.Scheme != "https" || link.User != nil {
		writeErr(w, http.StatusBadGateway, "auth state: invalid authorization URL")
		return
	}
	linkSite, err := auth.ResolveSite(&auth.Auth{Domain: link.Host})
	if err != nil || linkSite.International != site.International {
		writeErr(w, http.StatusBadGateway, "auth state: unexpected authorization site")
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create login session")
		return
	}
	loginID := hex.EncodeToString(id[:])
	p.loginMu.Lock()
	// 顺手回收过期会话，防"开弹窗走开"的 state 滞留。
	for s, session := range p.logins {
		if time.Since(session.Created) > loginTTL {
			delete(p.logins, s)
		}
	}
	if len(p.logins) >= 64 {
		p.loginMu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many pending login sessions")
		return
	}
	p.logins[loginID] = &loginSession{Created: time.Now(), Site: site, State: st.State}
	p.loginMu.Unlock()
	log.Printf("panel: OAuth login started site=%s", site.Host)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": st.AuthURL, "state": loginID, "site": input.Site, "product": input.Product})
}

// loginPoll 轮询登录态。未完成 → {done:false}；完成 → 建凭证、落盘、热加载、签到。
func (p *Panel) loginPoll(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		writeErr(w, http.StatusBadRequest, "missing state")
		return
	}
	p.loginMu.Lock()
	session := p.logins[state]
	if session == nil || time.Since(session.Created) > loginTTL {
		delete(p.logins, state)
		p.loginMu.Unlock()
		writeErr(w, http.StatusNotFound, "unknown or expired state（请重新发起添加账号）")
		return
	}
	if session.Result != nil {
		result := session.Result
		p.loginMu.Unlock()
		writeJSON(w, http.StatusOK, result)
		return
	}
	if session.Busy {
		p.loginMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"done": false})
		return
	}
	session.Busy = true
	p.loginMu.Unlock()
	defer func() {
		p.loginMu.Lock()
		session.Busy = false
		p.loginMu.Unlock()
	}()
	query := "?state=" + url.QueryEscape(session.State)

	// auth/token 是权威登录状态端点：pending 时业务 code 非 0（"login ing"）。
	tokRaw, _, err := loginJSON(session.Site, http.MethodGet, "/v2/plugin/auth/token"+query, "", "", nil)
	if err != nil {
		// pending / 未完成：面板前端继续轮询。
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": err.Error()})
		return
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(tokRaw, &tok); err != nil || tok.AccessToken == "" {
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "message": "waiting for login"})
		return
	}
	if tok.Domain == "" {
		tok.Domain = session.Site.Host
	}
	tokenSite, err := auth.ResolveSite(&auth.Auth{Domain: tok.Domain, AccessToken: tok.AccessToken})
	if err != nil || tokenSite != session.Site {
		writeErr(w, http.StatusBadGateway, "login token does not match the selected site and product")
		return
	}

	// 完成：取 uid/nickname（失败不阻塞，仅缺展示名）。
	var acct struct {
		UID          string `json:"uid"`
		EnterpriseID string `json:"enterpriseId"`
		Nickname     string `json:"nickname"`
	}
	acctRaw, _, acctErr := loginJSON(session.Site, http.MethodGet, "/v2/plugin/login/account"+query, tok.AccessToken, tokenSite.Host, nil)
	if acctErr == nil {
		_ = json.Unmarshal(acctRaw, &acct)
	}
	if acct.UID == "" {
		writeErr(w, http.StatusBadGateway, "login done but no uid（token 已发但账号信息获取失败，请重试）")
		return
	}
	// UID 来自上游响应，未经校验就用于拼文件名会被路径穿越利用
	// （filepath.Join("./auths", "workbuddy-../../evil.json") → auths/evil.json）。
	// UID 是腾讯侧账号标识，实测为 UUID（十六进制与连字符），故只放行 [A-Za-z0-9_-]。
	if !validUID(acct.UID) {
		writeErr(w, http.StatusBadGateway, "上游返回的 uid 含非法字符，拒绝落盘（防路径穿越）")
		return
	}

	// 凭证落盘（嵌套形，与 auths/ 目录既有格式一致）→ 热加载进池。
	if err := os.MkdirAll(p.cfg.AuthDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir auth dir: "+err.Error())
		return
	}
	var tokenDoc map[string]json.RawMessage
	_ = json.Unmarshal(tokRaw, &tokenDoc)
	tokenDoc["domain"], _ = json.Marshal(tokenSite.Host)
	if tok.ExpiresIn > 0 {
		tokenDoc["expiresAt"], _ = json.Marshal(time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix())
	}
	normalizedToken, _ := json.Marshal(tokenDoc)
	doc, _ := json.Marshal(map[string]json.RawMessage{"auth": normalizedToken, "account": acctRaw})
	a, err := auth.Parse(doc)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "invalid login credential")
		return
	}
	a.FilePath = filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", acct.UID))
	if previous := p.cfg.Pool.AuthByUID(acct.UID); previous != nil {
		previousSite, err := auth.ResolveSite(previous)
		if err != nil || previousSite != tokenSite {
			writeErr(w, http.StatusConflict, "account UID already belongs to a different site or product")
			return
		}
		a.RemoteName = previous.RemoteName
	}
	if err := a.SaveNew(); err != nil {
		writeErr(w, http.StatusInternalServerError, "save auth: "+err.Error())
		return
	}
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Revive(acct.UID) // 全新登录 = 人工恢复口径：清掉旧号遗留的禁用/冷却/熔断

	// 顺带签到 + 余额刷新（幂等；失败不影响登录结果，只体现在返回字段里）。
	checkinMsg := ""
	if !tokenSite.International {
		if err := p.cfg.Upstream.DailyCheckin(a); err != nil {
			checkinMsg = err.Error()
		}
	}
	remain := int64(-1)
	if rm, err := p.cfg.Upstream.UserResource(a); err == nil {
		remain = rm
		p.cfg.Pool.ReenableIfCredits(acct.UID, rm)
	}

	result := map[string]any{
		"done":            true,
		"uid":             acct.UID,
		"nickname":        acct.Nickname,
		"credits":         remain,
		"checkin_message": checkinMsg,
	}
	p.loginMu.Lock()
	session.Result = result
	p.loginMu.Unlock()
	log.Printf("panel: OAuth account loaded site=%s uid=%s", tokenSite.Host, acct.UID)
	writeJSON(w, http.StatusOK, result)
}
