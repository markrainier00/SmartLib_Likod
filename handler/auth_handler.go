package handler

import (
	"fmt"
	"os"
	"time"

	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	storage_go "github.com/supabase-community/storage-go"
)

func SendOTP(c *fiber.Ctx) error {
	var input services.SendOTPInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.SendOTPService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "An OTP is sent to email.",
		Data:    nil,
	})
}

func VerifyOTP(c *fiber.Ctx) error {
	var input services.VerifyOTPInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Email == "" || input.OTP == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.VerifyOTPService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "OTP verified successfully.",
		Data:    nil,
	})
}

func CheckSchoolID(c *fiber.Ctx) error {
	var input services.CheckSchoolIDInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.CheckSchoolIDService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "OTP verified successfully.",
		Data:    nil,
	})
}

func GetSchools(c *fiber.Ctx) error {
	schools, err := services.GetSchoolsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch schools",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Schools fetched successfully",
		Data:    schools,
	})
}

func RegisterHandler(c *fiber.Ctx) error {
	var savedPath string

	// 1. Handle image upload to Supabase Storage
	file, err := c.FormFile("school_id_image")
	if err == nil {
		src, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
				Message:   "Failed to open image",
				IsSuccess: false,
				Error:     err,
			})
		}
		defer src.Close()

		client := storage_go.NewClient(
			os.Getenv("DB_URL")+"/storage/v1",
			os.Getenv("DB_SERVICE_KEY"),
			nil,
		)

		filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)

		_, err = client.UploadFile("school-id-images", filename, src, storage_go.FileOptions{
			ContentType: &file.Header["Content-Type"][0],
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
				Message:   "Failed to upload image",
				IsSuccess: false,
				Error:     err,
			})
		}

		savedPath = os.Getenv("DB_URL") + "/storage/v1/object/public/school-id-images/" + filename
	}

	// 2. Build input
	input := services.RegisterInput{
		FirstName:     c.FormValue("firstname"),
		LastName:      c.FormValue("lastname"),
		Email:         c.FormValue("email"),
		SchoolID:      c.FormValue("school_id"),
		Department:    c.FormValue("department"),
		Program:       c.FormValue("program"),
		Year:          c.FormValue("year"),
		Password:      c.FormValue("password"),
		SchoolIDImage: savedPath,
	}

	// 3. Validate required fields
	if input.FirstName == "" || input.LastName == "" || input.Email == "" || input.SchoolID == "" ||
		input.Department == "" || input.Program == "" || input.Year == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	// 4. Call service
	user, err := services.RegisterUser(input)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	// 5. Send response
	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Registration successful. Your account must be approved by the library before you can sign in.",
		Data:    user,
	})
}

func Signin(c *fiber.Ctx) error {
	var input services.SigninInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Identifier == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	user, err := services.SigninUser(input)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	claims := jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(24 * time.Hour).Unix(), // expires in 24 hours
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Could not generate token",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Sign in successfull",
		Token:   tokenString,
		Data:    user,
	})
}

func ForgotPassword(c *fiber.Ctx) error {
	var input services.ForgotPasswordInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Identifier == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	services.ForgotPasswordService(input)

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "If an account exists for this email, you’ll receive a password reset link shortly.",
		Data:    nil,
	})
}

func ResetPassword(c *fiber.Ctx) error {
	var input services.ResetPasswordInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.Token == "" || input.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ResetPasswordService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Password reset successfully",
		Data:    nil,
	})
}

func ChangePassword(c *fiber.Ctx) error {
	var input services.ChangePasswordInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.CurrentPassword == "" || input.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	claims := c.Locals("claims").(jwt.MapClaims)
	userID := uint(claims["id"].(float64))

	if err := services.ChangePasswordService(userID, input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Password updated successfully",
		Data:    nil,
	})
}

func ChangeInformationHandler(c *fiber.Ctx) error {
	var input services.ChangeInformationInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.School_ID == "" || input.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ChangeInformationService(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Information change request submitted. Wait for the admnistrator to approve the request.",
		Data:    nil,
	})
}
