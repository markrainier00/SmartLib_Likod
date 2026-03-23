package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
)

func GetPendingUsers() ([]model.User, error) {
	var users []model.User
	result := database.DB.
		Where("status = ? AND role = ?", status.UserStatusPending, status.RoleStudent).
		Find(&users)
	return users, result.Error
}

func FindUserByID(id uint) (*model.User, error) {
	var user model.User
	result := database.DB.First(&user, id)
	return &user, result.Error
}

func ApproveUser(id uint) error {
	return database.DB.Model(&model.User{}).
		Where("id = ?", id).
		Update("status", status.UserStatusActive).Error
}

func ClearSchoolIDImage(id uint) error {
	return database.DB.Model(&model.User{}).
		Where("id = ?", id).
		Update("school_id_image", "").Error
}

func DeleteUser(id uint) error {
	return database.DB.Delete(&model.User{}, id).Error
}

func SaveRegistrationRequest(req *model.RegistrationRequest) error {
	return database.DB.Create(req).Error
}

func GetRegistrationHistory() ([]model.RegistrationRequest, error) {
	var history []model.RegistrationRequest
	result := database.DB.Order("actioned_at desc").Find(&history)
	return history, result.Error
}
