package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

func ApproveInformationRequest(id uint) error {
	var req model.InformationChangeRequest

	if err := database.DB.First(&req, id).Error; err != nil {
		return err
	}

	updates := map[string]interface{}{}
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Department != "" {
		updates["department"] = req.Department
	}
	if req.Program != "" {
		updates["program"] = req.Program
	}
	if req.Year != "" {
		updates["year"] = req.Year
	}

	if err := database.DB.Model(&model.User{}).
		Where("school_id = ?", req.SchoolID).
		Updates(updates).Error; err != nil {
		return err
	}

	return database.DB.Model(&req).
		Update("status", "Approved").Error
}

func RejectInformationRequest(id uint, reason string) error {
	return database.DB.Model(&model.InformationChangeRequest{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":        "Rejected",
			"reject_reason": reason,
		}).Error
}
