package docmost

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Workspace — минимальная модель воркспейса Docmost.
type Workspace struct {
	ID        string     `gorm:"column:id;type:uuid;primaryKey"`
	Name      string     `gorm:"column:name"`
	Hostname  *string    `gorm:"column:hostname"`
	DeletedAt *time.Time `gorm:"column:deleted_at"`
	CreatedAt time.Time  `gorm:"column:created_at"`
}

func (Workspace) TableName() string { return "workspaces" }

// User — модель таблицы users Docmost (только нужные поля).
type User struct {
	ID                   string     `gorm:"column:id;type:uuid;primaryKey;default:gen_uuid_v7()"`
	Name                 *string    `gorm:"column:name"`
	Email                string     `gorm:"column:email;not null"`
	EmailVerifiedAt      *time.Time `gorm:"column:email_verified_at"`
	Password             *string    `gorm:"column:password"`
	AvatarURL            *string    `gorm:"column:avatar_url"`
	Role                 *string    `gorm:"column:role"`
	InvitedByID          *string    `gorm:"column:invited_by_id"`
	WorkspaceID          *string    `gorm:"column:workspace_id"`
	Locale               *string    `gorm:"column:locale"`
	Timezone             *string    `gorm:"column:timezone"`
	LastActiveAt         *time.Time `gorm:"column:last_active_at"`
	LastLoginAt          *time.Time `gorm:"column:last_login_at"`
	DeactivatedAt        *time.Time `gorm:"column:deactivated_at"`
	DeletedAt            *time.Time `gorm:"column:deleted_at"`
	HasGeneratedPassword *bool      `gorm:"column:has_generated_password"`
	SCIMExternalID       *string    `gorm:"column:scim_external_id"`
	CreatedAt            time.Time  `gorm:"column:created_at"`
	UpdatedAt            time.Time  `gorm:"column:updated_at"`
}

func (User) TableName() string { return "users" }

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }

// upsertUser создаёт пользователя или обновляет пароль/имя существующего.
// Пароль — bcrypt-хеш случайного пароля, которым никто не пользуется:
// вход выполняется программно через API, а куки отдаются браузеру.
func (d *DocmostBackend) upsertUser(ctx context.Context, email, name, plainPassword, workspaceID string) error {
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return err
	}

	// Обновление пароля каждый раз, чтобы логин через API проходил
	// даже если пользователь сменил пароль вручную.
	now := time.Now()
	updates := map[string]any{
		"name":                   name,
		"password":               hash,
		"has_generated_password": true,
		"updated_at":             now,
	}

	res := d.db.WithContext(ctx).
		Model(&User{}).
		Where("email = ?", email).
		Where("workspace_id = ?", workspaceID).
		Where("deleted_at IS NULL").
		Updates(updates)

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		// Пользователь уже существовал (даже если уникальный ключ совпал по
		// email+workspace), пароль обновлён — логин через API пройдёт.
		return nil
	}

	newUser := User{
		ID:                   uuid.New().String(),
		Email:                email,
		Name:                 strPtr(name),
		Password:             &hash,
		WorkspaceID:          &workspaceID,
		Role:                 strPtr("member"),
		Locale:               strPtr("en-US"),
		HasGeneratedPassword: boolPtr(true),
		LastLoginAt:          &now,
	}
	return d.db.WithContext(ctx).Create(&newUser).Error
}
