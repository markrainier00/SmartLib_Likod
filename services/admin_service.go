package services

import (
	"errors"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/utils"
)

type ApproveInput struct {
	UserID uint `json:"user_id"`
}

type RejectInput struct {
	UserID uint   `json:"user_id"`
	Reason string `json:"reason"`
}

type UpdateUserStatusInput struct {
	SchoolID string `json:"school_id"`
	Status   string `json:"status"`
}

func GetPendingUsersService() ([]model.User, error) {
	return repositories.GetPendingUsers()
}

func ApproveUserService(input ApproveInput) error {
	user, err := repositories.FindUserByID(input.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	if user.Role != status.RoleStudent {
		return errors.New("only student accounts can be approved")
	}

	if user.Status != status.UserStatusPending {
		return errors.New("user is not pending approval")
	}

	if err := repositories.ApproveUser(user.ID); err != nil {
		return errors.New("failed to approve user")
	}

	record := &model.RegistrationRequest{
		UserID:        user.ID,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		SchoolID:      user.SchoolID,
		SchoolIDImage: user.SchoolIDImage,
		Program:       user.Program,
		Year:          user.Year,
		Action:        "Approved",
		Reason:        "",
		ActionedAt:    time.Now(),
	}

	if err := repositories.SaveRegistrationRequest(record); err != nil {
		return errors.New("failed to save history")
	}

	if err := utils.DeleteSchoolIDImage(user.SchoolIDImage); err != nil {
		return errors.New("user approved but failed to delete school ID image")
	}

	// clear dead URL from users table
	repositories.ClearSchoolIDImage(user.ID)

	if err := utils.SendApprovalEmail(user.Email, user.FirstName); err != nil {
		return errors.New("user approved but failed to send email")
	}

	return nil
}

func RejectUserService(input RejectInput) error {
	if input.Reason == "" {
		return errors.New("rejection reason is required")
	}

	user, err := repositories.FindUserByID(input.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	if user.Role != status.RoleStudent {
		return errors.New("only student accounts can be rejected")
	}

	if user.Status != status.UserStatusPending {
		return errors.New("user is not pending approval")
	}

	record := &model.RegistrationRequest{
		UserID:        user.ID,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Email:         user.Email,
		SchoolID:      user.SchoolID,
		SchoolIDImage: user.SchoolIDImage,
		Program:       user.Program,
		Year:          user.Year,
		Action:        "Rejected",
		Reason:        input.Reason,
		ActionedAt:    time.Now(),
	}

	if err := repositories.SaveRegistrationRequest(record); err != nil {
		return errors.New("failed to save history")
	}

	if err := utils.DeleteSchoolIDImage(user.SchoolIDImage); err != nil {
		return errors.New("user rejected but failed to delete school ID image")
	}

	if err := utils.SendRejectionEmail(user.Email, user.FirstName, input.Reason); err != nil {
		return errors.New("user rejected but failed to send email")
	}

	// no need to ClearSchoolIDImage here since user gets deleted anyway
	if err := repositories.DeleteUser(user.ID); err != nil {
		return errors.New("failed to delete user")
	}

	return nil
}

func GetRegistrationHistoryService() ([]model.RegistrationRequest, error) {
	return repositories.GetRegistrationHistory()
}

func GetAllUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	return users, nil
}

func UpdateUserStatusService(input UpdateUserStatusInput) error {
	result := database.DB.Model(&model.User{}).
		Where("school_id = ?", input.SchoolID).
		Updates(map[string]interface{}{
			"status":        input.Status,
			"penalty_count": 0,
		})

	if result.Error != nil {
		return errors.New("failed to update user status")
	}

	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func DeleteUserService(schoolID string) error {
	result := database.DB.Where("school_id = ?", schoolID).Delete(&model.User{})

	if result.Error != nil {
		return errors.New("failed to delete user")
	}

	if result.RowsAffected == 0 {
		return errors.New("user not found")
	}

	return nil
}

func GetAllRequestsService() ([]model.Transaction, error) {
	var transactions []model.Transaction
	result := database.DB.Find(&transactions)
	if result.Error != nil {
		return nil, result.Error
	}
	return transactions, nil
}
