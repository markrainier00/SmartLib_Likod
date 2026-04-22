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

	err := database.DB.Model(&model.User{}).
		Where("school_id = ?", req.SchoolID).
		Updates(map[string]interface{}{
			"email":      req.Email,
			"department": req.Department,
			"program":    req.Program,
			"year":       req.Year,
		}).Error

	if err != nil {
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
