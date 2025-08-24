package plane

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type User struct {
	Password          string     `gorm:"column:password;not null"`
	LastLogin         *time.Time `gorm:"column:last_login"`
	ID                string     `gorm:"primaryKey;column:id;type:uuid;default:uuid_generate_v4()"`
	Username          string     `gorm:"column:username;not null"`
	MobileNumber      string     `gorm:"column:mobile_number"`
	Email             string     `gorm:"column:email;unique"`
	FirstName         string     `gorm:"column:first_name;not null"`
	LastName          string     `gorm:"column:last_name;not null"`
	Avatar            string     `gorm:"column:avatar;not null"`
	DateJoined        time.Time  `gorm:"column:date_joined;not null"`
	CreatedAt         time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt         time.Time  `gorm:"column:updated_at;not null"`
	LastLocation      string     `gorm:"column:last_location;not null"`
	CreatedLocation   string     `gorm:"column:created_location;not null"`
	IsSuperuser       bool       `gorm:"column:is_superuser;not null"`
	IsManaged         bool       `gorm:"column:is_managed;not null"`
	IsPasswordExpired bool       `gorm:"column:is_password_expired;not null"`
	IsActive          bool       `gorm:"column:is_active;not null"`
	IsStaff           bool       `gorm:"column:is_staff;not null"`
	IsEmailVerified   bool       `gorm:"column:is_email_verified;not null"`
	IsPasswordAutoset bool       `gorm:"column:is_password_autoset;not null"`
	Token             string     `gorm:"column:token;not null"`
	UserTimezone      string     `gorm:"column:user_timezone;not null"`
	LastActive        *time.Time `gorm:"column:last_active"`
	LastLoginTime     *time.Time `gorm:"column:last_login_time"`
	LastLogoutTime    *time.Time `gorm:"column:last_logout_time"`
	LastLoginIP       string     `gorm:"column:last_login_ip;not null"`
	LastLogoutIP      string     `gorm:"column:last_logout_ip;not null"`
	LastLoginMedium   string     `gorm:"column:last_login_medium;not null"`
	LastLoginUagent   string     `gorm:"column:last_login_uagent;not null"`
	TokenUpdatedAt    *time.Time `gorm:"column:token_updated_at"`
	IsBot             bool       `gorm:"column:is_bot;not null"`
	CoverImage        *string    `gorm:"column:cover_image"`
	DisplayName       string     `gorm:"column:display_name;not null"`
	AvatarAssetID     *string    `gorm:"column:avatar_asset_id"`
	CoverImageAssetID *string    `gorm:"column:cover_image_asset_id"`
	BotType           *string    `gorm:"column:bot_type"`
	IsEmailValid      bool       `gorm:"column:is_email_valid;not null"`
	MaskedAt          *time.Time `gorm:"column:masked_at"`
}

func (pb *PlaneBackend) createOrUpdateUser(email, firstName, lastName, randomPwd string) (*User, error) {
	hashedPwd, err := Generate(randomPwd)
	if err != nil {
		return nil, err
	}
	ok, err := Verify(randomPwd, hashedPwd)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid password hash")
	}
	now := time.Now()
	tokenGenerated := strings.ReplaceAll(uuid.New().String()+uuid.New().String(), "-", "")
	user := User{
		Username:          email,
		MobileNumber:      "",
		Email:             email,
		FirstName:         firstName,
		LastName:          lastName,
		Password:          hashedPwd,
		Avatar:            "",
		DateJoined:        time.Now(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		LastLogin:         nil,
		IsSuperuser:       false,
		IsManaged:         false,
		IsPasswordExpired: false,
		IsActive:          true,
		IsStaff:           false,
		IsEmailVerified:   true,
		IsPasswordAutoset: false,
		Token:             tokenGenerated,
		UserTimezone:      "UTC", // Установите значение по умолчанию
		LastLoginTime:     nil,
		LastLogoutTime:    nil,
		LastLoginIP:       "",
		LastLogoutIP:      "",
		LastLoginMedium:   "",
		LastLoginUagent:   "",
		TokenUpdatedAt:    &now,
		IsBot:             false,
		CoverImage:        nil,
		DisplayName:       fmt.Sprintf("%s %s", firstName, lastName),
		AvatarAssetID:     nil,
		CoverImageAssetID: nil,
		BotType:           nil,
		LastLocation:      "",
		IsEmailValid:      true,
		MaskedAt:          nil,
	}

	// Попробуем найти существующего пользователя
	_ = pb.db.Where("email = ?", email).Limit(1).Find(&user)

	if user.ID == "" {
		// Если пользователь не найден, создаем нового
		user.ID = uuid.New().String()
		if err := pb.db.Create(&user).Error; err != nil {
			return &user, err
		}
	} else {
		// Если пользователь найден, обновляем его данные
		user.FirstName = firstName
		user.LastName = lastName
		user.DisplayName = fmt.Sprintf("%s %s", firstName, lastName)
		user.Password = hashedPwd
		user.UpdatedAt = time.Now()
		if user.TokenUpdatedAt == nil || user.Token == "" {
			user.TokenUpdatedAt = &now
			user.Token = tokenGenerated
		}
		if err := pb.db.Save(&user).Error; err != nil {
			return &user, err
		}
	}
	return &user, nil
}
