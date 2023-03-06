package main

import (
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/brianvoe/sjwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	Id       int    `json:"id" gorm:"primaryKey"`
	Login    string `json:"login" gorm:"column:login;"`
	Password string `json:"password" gorm:"column:password;"`
	Role     int    `json:"role_id" gorm:"column:role;"`
}

func (User) TableName() string {
	return "users"
}

// service layer
type _db struct {
	_instance *gorm.DB
}

var __db = _db{}

func (_db *_db) init() *gorm.DB {
	if _db._instance != nil {
		return _db._instance
	}
	_db._instance, _ = gorm.Open(sqlite.Open("db"), &gorm.Config{})
	return _db._instance
}

type Hash struct{}

func (Hash Hash) Generate(s string) (string, error) {
	saltedBytes := []byte(s)
	hashedBytes, err := bcrypt.GenerateFromPassword(saltedBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	hash := string(hashedBytes[:])
	return hash, nil
}

func (Hash Hash) Compare(hash string, s string) error {
	incoming := []byte(s)
	existing := []byte(hash)
	return bcrypt.CompareHashAndPassword(existing, incoming)
}

//

func _register(login string, password string, role int) {
	var __user User
	r := __db.init().Where("login = ?", login).Limit(1).Find(&__user)
	if r.RowsAffected > 0 {
		return
	}
	password, _ = Hash{}.Generate(password)
	user := User{Login: login, Password: password, Role: role}
	__db.init().Create(&user)
}

var secretKey = []byte("abracadabra")

func _login(login string, password string) string {
	var _user User
	__db.init().Where("login = ?", login).Find(&_user)
	err := Hash{}.Compare(_user.Password, password)
	if err != nil {
		return ""
	}
	fmt.Println(err)
	claims := sjwt.New()
	claims.Set("login", _user.Login)
	claims.SetNotBeforeAt(time.Now().Add(time.Hour * 1))
	jwt := claims.Generate(secretKey)
	return jwt
}

func _auth(jwt string) string {
	hasVerified := sjwt.Verify(jwt, secretKey)
	if !hasVerified {
		return ""
	}
	claims, _ := sjwt.Parse(jwt)
	err := claims.Validate()
	if err != nil {
		return ""
	}
	res, _ := claims.GetStr("login")

	return res
}

type Jwt struct {
	Jwt string `json:"jwt"`
}

func main() {
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowMethods:     "GET, POST, PATCH, DELETE",
		AllowCredentials: true,
	}))

	app.Get("/api/register/:login/:password/", func(c *fiber.Ctx) error {
		login := c.Params("login")
		password := c.Params("password")
		_register(login, password, 1)
		return c.JSON(&fiber.Map{
			"result": true,
		})
	})

	app.Get("/api/login/:login/:password", func(c *fiber.Ctx) error {
		login := c.Params("login")
		password := c.Params("password")
		jwt := _login(login, password)
		return c.JSON(&fiber.Map{
			"result": jwt,
		})
	})

	app.Post("/api/auth/", func(c *fiber.Ctx) error {
		jwt := new(Jwt)
		if err := c.BodyParser(jwt); err != nil {
			return err
		}
		res := _auth(jwt.Jwt)
		return c.JSON(&fiber.Map{
			"login": res,
		})
	})

	log.Fatal(app.Listen(":3000"))

}
