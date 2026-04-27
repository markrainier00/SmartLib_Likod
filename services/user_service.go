package services

import (
	"errors"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type UpdateUserStatusInput struct {
	SchoolID string `json:"school_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

type SchoolInput struct {
	Department string `json:"department"`
	Program    string `json:"program"`
	Duration   int    `json:"duration"`
}

func CreateSchoolService(input SchoolInput) (*model.School, error) {
	school := &model.School{
		Department: input.Department,
		Program:    input.Program,
		Duration:   input.Duration,
	}
	err := repositories.CreateSchool(school)
	return school, err
}

func UpdateSchoolService(id uint, input SchoolInput) error {
	_, err := repositories.FindSchoolByID(id)
	if err != nil {
		return errors.New("program not found")
	}
	return repositories.UpdateSchool(id, model.School{
		Department: input.Department,
		Program:    input.Program,
		Duration:   input.Duration,
	})
}

func DeleteSchoolService(id uint) error {
	_, err := repositories.FindSchoolByID(id)
	if err != nil {
		return errors.New("program not found")
	}
	return repositories.DeleteSchool(id)
}

func GetSchoolService() ([]model.School, error) {
	var school []model.School
	result := database.DB.Order("department asc, program asc").Find(&school)
	return school, result.Error
}

func GetWholeUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	return users, result.Error
}

func GetAllUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("status != ? AND status != ? AND role != ?", "Pending", "Archived", "Admin").Find(&users)
	return users, result.Error
}

func GetPendingUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("status = ?", "Pending").Find(&users)
	return users, result.Error
}

func GetArchivedStudentsService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("role = ? AND status = ?", "Student", "Archived").Find(&users)
	return users, result.Error
}

func GetArchivedUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("status = ?", "Archived").Find(&users)
	return users, result.Error
}

func GetStudentUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("role = ? AND status != ? AND status != ?", "Student", "Pending", "Archived").Find(&users)
	return users, result.Error
}

func GetSpecificUserService(schoolID string) ([]model.User, error) {
	var users []model.User
	result := database.DB.Where("school_id = ?", schoolID).Find(&users)
	return users, result.Error
}

func GetAllRequestsService() ([]model.Transaction, error) {
	var transactions []model.Transaction
	result := database.DB.Find(&transactions)
	return transactions, result.Error
}

func GetRegistrationHistoryService() ([]model.RegistrationRequest, error) {
	return repositories.GetRegistrationHistory()
}

func GetAllAccountsService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	return users, result.Error
}

func GetInformationChangeService() ([]model.InformationChangeRequest, error) {
	var request []model.InformationChangeRequest
	result := database.DB.Where("status = ?", "Pending").Find(&request)
	return request, result.Error
}
