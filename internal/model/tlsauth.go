package model

const TLS_AUTH_KEY_LENGTH = 20

// Key used for generating/verifying HMAC
type TLSAuthKey [TLS_AUTH_KEY_LENGTH]byte
