package main

import (
	"context"
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"

	"main/pkg/api"

	"github.com/brianvoe/sjwt"
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
	_user.Password = ""
	claims, _ := sjwt.ToClaims(_user)
	claims.SetExpiresAt(time.Now().Add(time.Hour * 1))
	jwt := claims.Generate(secretKey)
	return jwt
}

func _auth(jwt string) User {
	hasVerified := sjwt.Verify(jwt, secretKey)
	if !hasVerified {
		return User{}
	}
	claims, _ := sjwt.Parse(jwt)
	err := claims.Validate()
	if err != nil {
		return User{}
	}
	var _user User
	_user.Login, _ = claims.GetStr("login")
	role, _ := claims.GetStr("role_id")
	_user.Role, _ = strconv.Atoi(role)
	return _user
}

type Jwt struct {
	Jwt string `json:"jwt"`
}

type GRPCServer struct {
	api.UnimplementedUserServer
}

func (s GRPCServer) Auth(ctx context.Context, req *api.AuthRequest) (*api.AuthResponse, error) {
	login := req.Login
	password := req.Password
	jwt := _login(login, password)
	return &api.AuthResponse{Jwt: jwt}, nil
}

func main() {

	s := grpc.NewServer()
	srv := &GRPCServer{}
	api.RegisterUserServer(s, srv)
	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Serve(l); err != nil {
		log.Fatal(err)
	}

	//http
	/*
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
				"user": res,
			})
		})

		log.Fatal(app.Listen(":3000"))
	*/
	//grpc

}
