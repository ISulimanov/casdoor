package pt_af_logic

const (
	// todo: should be moved to vault/env
	afHost = "https://m1-26.af.rd.ptsecurity.ru/api/ptaf/v4"

	// ptlmHost using for hyperlinks for ptlm in email notification
	ptlmHost = "http://158.160.34.146:8000"

	afLogin       = "admin"
	afPwd         = "P@ssw0rd"
	afFingerPrint = "qwe"
)

const (
	lowerCharSet          = "abcdedfghijklmnopqrstuvwxyz"
	upperCharSet          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberSet             = "0123456789"
	specialCharSet        = "!#$%&\\\\'*+\\-/=?^\\`{|}~(_)."
	allCharSet            = lowerCharSet + upperCharSet + numberSet
	allCharSetWithSpecial = lowerCharSet + upperCharSet + numberSet + specialCharSet
)
