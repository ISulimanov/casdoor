// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	*User
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Scope     string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

type UserShort struct {
	Owner string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name  string `xorm:"varchar(100) notnull pk" json:"name"`
}

type UserWithoutThirdIdp struct {
	Owner               string            `xorm:"varchar(100) notnull pk" json:"owner"`
	Name                string            `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime         string            `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime         string            `xorm:"varchar(100)" json:"updatedTime"`
	Id                  string            `xorm:"varchar(100) index" json:"id"`
	Type                string            `xorm:"varchar(100)" json:"type"`
	Password            string            `xorm:"varchar(100)" json:"password"`
	PasswordSalt        string            `xorm:"varchar(100)" json:"passwordSalt"`
	DisplayName         string            `xorm:"varchar(100)" json:"displayName"`
	FirstName           string            `xorm:"varchar(100)" json:"firstName"`
	LastName            string            `xorm:"varchar(100)" json:"lastName"`
	Avatar              string            `xorm:"varchar(500)" json:"avatar"`
	PermanentAvatar     string            `xorm:"varchar(500)" json:"permanentAvatar"`
	Email               string            `xorm:"varchar(100) index" json:"email"`
	EmailVerified       bool              `json:"emailVerified"`
	Phone               string            `xorm:"varchar(100) index" json:"phone"`
	Location            string            `xorm:"varchar(100)" json:"location"`
	Address             []string          `json:"address"`
	Affiliation         string            `xorm:"varchar(100)" json:"affiliation"`
	Title               string            `xorm:"varchar(100)" json:"title"`
	IdCardType          string            `xorm:"varchar(100)" json:"idCardType"`
	IdCard              string            `xorm:"varchar(100) index" json:"idCard"`
	Homepage            string            `xorm:"varchar(100)" json:"homepage"`
	Bio                 string            `xorm:"varchar(100)" json:"bio"`
	Tag                 string            `xorm:"varchar(100)" json:"tag"`
	Region              string            `xorm:"varchar(100)" json:"region"`
	Language            string            `xorm:"varchar(100)" json:"language"`
	Gender              string            `xorm:"varchar(100)" json:"gender"`
	Birthday            string            `xorm:"varchar(100)" json:"birthday"`
	Education           string            `xorm:"varchar(100)" json:"education"`
	Score               int               `json:"score"`
	Karma               int               `json:"karma"`
	Ranking             int               `json:"ranking"`
	IsDefaultAvatar     bool              `json:"isDefaultAvatar"`
	IsOnline            bool              `json:"isOnline"`
	IsAdmin             bool              `json:"isAdmin"`
	IsGlobalAdmin       bool              `json:"isGlobalAdmin"`
	IsForbidden         bool              `json:"isForbidden"`
	IsDeleted           bool              `json:"isDeleted"`
	SignupApplication   string            `xorm:"varchar(100)" json:"signupApplication"`
	Hash                string            `xorm:"varchar(100)" json:"hash"`
	PreHash             string            `xorm:"varchar(100)" json:"preHash"`
	CreatedIp           string            `xorm:"varchar(100)" json:"createdIp"`
	LastSigninTime      string            `xorm:"varchar(100)" json:"lastSigninTime"`
	LastSigninIp        string            `xorm:"varchar(100)" json:"lastSigninIp"`
	Ldap                string            `xorm:"ldap varchar(100)" json:"ldap"`
	Properties          map[string]string `json:"properties"`
	Roles               []*Role           `xorm:"-" json:"roles"`
	Permissions         []*Permission     `xorm:"-" json:"permissions"`
	LastSigninWrongTime string            `xorm:"varchar(100)" json:"lastSigninWrongTime"`
	SigninWrongTimes    int               `json:"signinWrongTimes"`
}

type ClaimsShort struct {
	*UserShort
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Scope     string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

type ClaimsWithoutThirdIdp struct {
	*UserWithoutThirdIdp
	TokenType string `json:"tokenType,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Scope     string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func getShortUser(user *User) *UserShort {
	res := &UserShort{
		Owner: user.Owner,
		Name:  user.Name,
	}
	return res
}

func getUserWithoutThirdIdp(user *User) *UserWithoutThirdIdp {
	res := &UserWithoutThirdIdp{
		Owner:       user.Owner,
		Name:        user.Name,
		CreatedTime: user.CreatedTime,
		UpdatedTime: user.UpdatedTime,

		Id:                user.Id,
		Type:              user.Type,
		Password:          user.Password,
		PasswordSalt:      user.PasswordSalt,
		DisplayName:       user.DisplayName,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Avatar:            user.Avatar,
		PermanentAvatar:   user.PermanentAvatar,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Phone:             user.Phone,
		Location:          user.Location,
		Address:           user.Address,
		Affiliation:       user.Affiliation,
		Title:             user.Title,
		IdCardType:        user.IdCardType,
		IdCard:            user.IdCard,
		Homepage:          user.Homepage,
		Bio:               user.Bio,
		Tag:               user.Tag,
		Region:            user.Region,
		Language:          user.Language,
		Gender:            user.Gender,
		Birthday:          user.Birthday,
		Education:         user.Education,
		Score:             user.Score,
		Karma:             user.Karma,
		Ranking:           user.Ranking,
		IsDefaultAvatar:   user.IsDefaultAvatar,
		IsOnline:          user.IsOnline,
		IsAdmin:           user.IsAdmin,
		IsGlobalAdmin:     user.IsGlobalAdmin,
		IsForbidden:       user.IsForbidden,
		IsDeleted:         user.IsDeleted,
		SignupApplication: user.SignupApplication,
		Hash:              user.Hash,
		PreHash:           user.PreHash,

		CreatedIp:      user.CreatedIp,
		LastSigninTime: user.LastSigninTime,
		LastSigninIp:   user.LastSigninIp,

		Ldap:       user.Ldap,
		Properties: user.Properties,

		Roles:       user.Roles,
		Permissions: user.Permissions,

		LastSigninWrongTime: user.LastSigninWrongTime,
		SigninWrongTimes:    user.SigninWrongTimes,
	}

	return res
}

func getShortClaims(claims Claims) ClaimsShort {
	res := ClaimsShort{
		UserShort:        getShortUser(claims.User),
		TokenType:        claims.TokenType,
		Nonce:            claims.Nonce,
		Scope:            claims.Scope,
		RegisteredClaims: claims.RegisteredClaims,
	}
	return res
}

func getClaimsWithoutThirdIdp(claims Claims) ClaimsWithoutThirdIdp {
	res := ClaimsWithoutThirdIdp{
		UserWithoutThirdIdp: getUserWithoutThirdIdp(claims.User),
		TokenType:           claims.TokenType,
		Nonce:               claims.Nonce,
		Tag:                 claims.Tag,
		Scope:               claims.Scope,
		RegisteredClaims:    claims.RegisteredClaims,
	}
	return res
}

func refineUser(user *User) *User {
	user.Password = ""

	if user.Address == nil {
		user.Address = []string{}
	}
	if user.Properties == nil {
		user.Properties = map[string]string{}
	}
	if user.Roles == nil {
		user.Roles = []*Role{}
	}
	if user.Permissions == nil {
		user.Permissions = []*Permission{}
	}

	return user
}

func generateBaseClaims(application *Application, user *User, nonce string, scope string, host string) Claims {
	nowTime := time.Now()

	user = refineUser(user)
	_, originBackend := getOriginFromHost(host)

	name := util.GenerateId()
	jti := fmt.Sprintf("%s/%s", application.Owner, name)

	claims := Claims{
		User:  user,
		Nonce: nonce,
		Tag:   user.Tag,
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    originBackend,
			Subject:   user.Id,
			NotBefore: jwt.NewNumericDate(nowTime),
			IssuedAt:  jwt.NewNumericDate(nowTime),
		},
	}
	return claims
}

func generateToken(
	application *Application, user *User, nonce string, scope string, host string, claims jwt.Claims,
) (string, error) {
	var token *jwt.Token

	token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	cert := getCertByApplication(application)

	// RSA private key
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	if err != nil {
		return "", err
	}

	token.Header["kid"] = cert.Name
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, err
}

func generateJwtToken(
	application *Application, user *User, nonce string, scope string, host string,
) (string, string, string, error) {
	tokenName := util.GenerateId()
	nowTime := time.Now()
	expireTime := nowTime.Add(time.Duration(application.ExpireInHours) * time.Hour)

	claims := generateBaseClaims(application, user, nonce, scope, host)

	claims.TokenType = "access-token"
	claims.ExpiresAt = jwt.NewNumericDate(expireTime)
	claims.Audience = []string{application.ClientId}

	var claimsRes jwt.Claims

	if application.TokenFormat == "JWT-Empty" {
		claimsRes = getShortClaims(claims)
	} else {
		claimsRes = getClaimsWithoutThirdIdp(claims)
	}

	token, err := generateToken(application, user, nonce, scope, host, claimsRes)
	if err != nil {
		return "", "", "", err
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsRes)
	cert := getCertByApplication(application)
	// RSA private key
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	if err != nil {
		return "", "", "", err
	}
	refreshTokenString, err := refreshToken.SignedString(key)

	return token, refreshTokenString, tokenName, nil
}

func generateSubscriptionToken(
	application *Application, user *User, subscription *Subscription, nonce string, scope string, host string,
) (string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(time.Duration(subscription.Duration) * time.Hour * 24)

	claims := generateBaseClaims(application, user, nonce, scope, host)

	claims.TokenType = "subscription-token"
	claims.TokenType = "subscription-token"
	claims.ExpiresAt = jwt.NewNumericDate(expireTime)

	claimsShort := getShortClaims(claims)

	subscriptionToken, err := generateToken(application, user, nonce, scope, host, claimsShort)
	return subscriptionToken, err
}

func ParseJwtToken(token string, cert *Cert) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// RSA certificate
		certificate, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
		if err != nil {
			return nil, err
		}

		return certificate, nil
	})

	if t != nil {
		if claims, ok := t.Claims.(*Claims); ok && t.Valid {
			return claims, nil
		}
	}

	return nil, err
}

func ParseJwtTokenByApplication(token string, application *Application) (*Claims, error) {
	return ParseJwtToken(token, getCertByApplication(application))
}
