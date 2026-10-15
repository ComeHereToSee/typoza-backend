package httpapi

import (
	"net/http"

	"github.com/ComeHereToSee/typoza-backend/internal/service"
)

// —— 未认证:prelogin / register / login / refresh / recover ——

type preloginRequest struct {
	Email string `json:"email"`
}

func (s *Server) prelogin(w http.ResponseWriter, r *http.Request) {
	var req preloginRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	kdf, err := s.svc.Prelogin(r.Context(), email)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"kdf": kdf})
}

type registerRequest struct {
	Email                       string              `json:"email"`
	KDF                         *service.KDF        `json:"kdf"`
	AuthKey                     string              `json:"authKey"`
	EncryptedAccountKey         string              `json:"encryptedAccountKey"`
	RecoveryAuthKey             string              `json:"recoveryAuthKey"`
	RecoveryEncryptedAccountKey string              `json:"recoveryEncryptedAccountKey"`
	Device                      *service.DeviceInfo `json:"device"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	in, err := req.validate()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	in.IP = requestInfo(r).ip
	sess, err := s.svc.Register(r.Context(), in)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, sess)
}

func (req registerRequest) validate() (service.RegisterInput, error) {
	var in service.RegisterInput
	var err error
	if in.Email, err = normalizeEmail(req.Email); err != nil {
		return in, err
	}
	if err = checkKDF("kdf", req.KDF); err != nil {
		return in, err
	}
	in.KDF = *req.KDF
	if in.AuthKey, err = decodeKey("authKey", req.AuthKey); err != nil {
		return in, err
	}
	if in.RecoveryAuthKey, err = decodeKey("recoveryAuthKey", req.RecoveryAuthKey); err != nil {
		return in, err
	}
	if err = checkB64Text("encryptedAccountKey", req.EncryptedAccountKey, maxWrappedKeyBytes); err != nil {
		return in, err
	}
	if err = checkB64Text("recoveryEncryptedAccountKey", req.RecoveryEncryptedAccountKey, maxWrappedKeyBytes); err != nil {
		return in, err
	}
	in.EncryptedAccountKey = req.EncryptedAccountKey
	in.RecoveryEncryptedAccountKey = req.RecoveryEncryptedAccountKey
	if in.Device, err = checkDevice(req.Device); err != nil {
		return in, err
	}
	return in, nil
}

type loginRequest struct {
	Email    string              `json:"email"`
	AuthKey  string              `json:"authKey"`
	TOTPCode string              `json:"totpCode"`
	Device   *service.DeviceInfo `json:"device"`
	DeviceID string              `json:"deviceId"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	// 每邮箱限流放在昂贵的 Argon2 之前,格式校验之后(格式错误不消耗该邮箱的额度)。
	if !s.allowEmail(w, r, "login:"+email) {
		return
	}
	in := service.LoginInput{Email: email, TOTPCode: req.TOTPCode, IP: requestInfo(r).ip}
	if in.AuthKey, err = decodeKey("authKey", req.AuthKey); err != nil {
		s.writeError(w, r, err)
		return
	}
	if in.Device, err = checkDevice(req.Device); err != nil {
		s.writeError(w, r, err)
		return
	}
	if req.DeviceID != "" {
		if err := checkUUID("deviceId", req.DeviceID); err != nil {
			s.writeError(w, r, err)
			return
		}
		in.DeviceID = req.DeviceID
	}
	sess, err := s.svc.Login(r.Context(), in)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, sess)
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	tokens, err := s.svc.Refresh(r.Context(), req.RefreshToken, requestInfo(r).ip)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, tokens)
}

type recoverBeginRequest struct {
	Email           string `json:"email"`
	RecoveryAuthKey string `json:"recoveryAuthKey"`
}

func (s *Server) recoverBegin(w http.ResponseWriter, r *http.Request) {
	var req recoverBeginRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if !s.allowEmail(w, r, "recover:"+email) {
		return
	}
	key, err := decodeKey("recoveryAuthKey", req.RecoveryAuthKey)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	res, err := s.svc.RecoverBegin(r.Context(), email, key, requestInfo(r).ip)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

type recoverFinishRequest struct {
	RecoveryToken       string              `json:"recoveryToken"`
	KDF                 *service.KDF        `json:"kdf"`
	AuthKey             string              `json:"authKey"`
	EncryptedAccountKey string              `json:"encryptedAccountKey"`
	Device              *service.DeviceInfo `json:"device"`
}

func (s *Server) recoverFinish(w http.ResponseWriter, r *http.Request) {
	var req recoverFinishRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	in := service.RecoverFinishInput{RecoveryToken: req.RecoveryToken, IP: requestInfo(r).ip}
	var err error
	if err = checkKDF("kdf", req.KDF); err != nil {
		s.writeError(w, r, err)
		return
	}
	in.KDF = *req.KDF
	if in.AuthKey, err = decodeKey("authKey", req.AuthKey); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err = checkB64Text("encryptedAccountKey", req.EncryptedAccountKey, maxWrappedKeyBytes); err != nil {
		s.writeError(w, r, err)
		return
	}
	in.EncryptedAccountKey = req.EncryptedAccountKey
	if in.Device, err = checkDevice(req.Device); err != nil {
		s.writeError(w, r, err)
		return
	}
	sess, err := s.svc.RecoverFinish(r.Context(), in)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, sess)
}

// —— 已认证:登出、账号、改密、删号、二次验证、设备 ——

func (s *Server) logout(w http.ResponseWriter, r *http.Request, p service.Principal) {
	if err := s.svc.Logout(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, p service.Principal) {
	acc, err := s.svc.Account(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, acc)
}

type changePasswordRequest struct {
	AuthKey                string       `json:"authKey"`
	NewKDF                 *service.KDF `json:"newKdf"`
	NewAuthKey             string       `json:"newAuthKey"`
	NewEncryptedAccountKey string       `json:"newEncryptedAccountKey"`
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req changePasswordRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	var in service.ChangePasswordInput
	var err error
	if in.AuthKey, err = decodeKey("authKey", req.AuthKey); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err = checkKDF("newKdf", req.NewKDF); err != nil {
		s.writeError(w, r, err)
		return
	}
	in.NewKDF = *req.NewKDF
	if in.NewAuthKey, err = decodeKey("newAuthKey", req.NewAuthKey); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err = checkB64Text("newEncryptedAccountKey", req.NewEncryptedAccountKey, maxWrappedKeyBytes); err != nil {
		s.writeError(w, r, err)
		return
	}
	in.NewEncryptedAccountKey = req.NewEncryptedAccountKey
	if err := s.svc.ChangePassword(r.Context(), p, in); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type deleteAccountRequest struct {
	AuthKey string `json:"authKey"`
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request, p service.Principal) {
	var req deleteAccountRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return
	}
	key, err := decodeKey("authKey", req.AuthKey)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.DeleteAccount(r.Context(), p, key); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) totpSetup(w http.ResponseWriter, r *http.Request, p service.Principal) {
	res, err := s.svc.TOTPSetup(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// decodeTOTPCode 解析验证码请求,并按账号限流:6 位验证码 ±1 步只有约百万分之三的猜中率,
// 但已认证接口每账号 1200 次/分钟的额度足以在数小时内暴力猜中,所以二次验证改用每账号 10 次/分钟。
func (s *Server) decodeTOTPCode(w http.ResponseWriter, r *http.Request, p service.Principal) (string, bool) {
	var req totpCodeRequest
	if err := decodeJSON(w, r, jsonBodyLimit, &req); err != nil {
		s.writeError(w, r, err)
		return "", false
	}
	if !s.allowEmail(w, r, "totp:"+p.UserID) {
		return "", false
	}
	return req.Code, true
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request, p service.Principal) {
	code, ok := s.decodeTOTPCode(w, r, p)
	if !ok {
		return
	}
	if err := s.svc.TOTPEnable(r.Context(), p, code); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, p service.Principal) {
	code, ok := s.decodeTOTPCode(w, r, p)
	if !ok {
		return
	}
	if err := s.svc.TOTPDisable(r.Context(), p, code); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, p service.Principal) {
	list, err := s.svc.Devices(r.Context(), p)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"devices": list})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, p service.Principal) {
	id := r.PathValue("deviceId")
	if err := checkUUID("deviceId", id); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.svc.RevokeDevice(r.Context(), p, id); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
