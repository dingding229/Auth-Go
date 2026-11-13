// Package bootstrap contains first-start initialization, not login services.
package bootstrap

import (
	"authgo/internal/model"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminResult struct {
	Created bool
}

// EnsureAdmin never resets credentials on subsequent starts. Without an explicit
// password it leaves initialization to the one-time setup flow.
func EnsureAdmin(database *gorm.DB, username, password string) (AdminResult, error) {
	var result AdminResult
	err := database.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.Admin{}).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return nil
		}
		if password == "" {
			return nil
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("初始化管理员密码: %w", err)
		}
		admin := model.Admin{Username: username, PasswordHash: string(hash)}
		if err := tx.Create(&admin).Error; err != nil {
			return err
		}
		result.Created = true
		return nil
	})
	if err != nil {
		return AdminResult{}, err
	}
	return result, nil
}
