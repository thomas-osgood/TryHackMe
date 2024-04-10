package structs

// structure representing the format a login
// request will have.
type LoginRequest struct {
	Captcha  int    `json:"captcha"`
	Password string `json:"password"`
	Username string `json:"username"`
}
