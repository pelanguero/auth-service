package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Usuario struct {
	ID     primitive.ObjectID
	Nombre string
	Correo string
	Foto   string
	Clave  string
}
type Libro struct {
	ID      primitive.ObjectID
	usuario primitive.ObjectID
	archivo string
}
type Seccion struct {
	ID       primitive.ObjectID
	libro    primitive.ObjectID
	usuario  primitive.ObjectID
	paginaIn int
	paginaFi int
}
type Pagina struct {
	ID      primitive.ObjectID
	usuario primitive.ObjectID //correo
	libro   primitive.ObjectID
	seccion primitive.ObjectID
	texto   string
	pagina  int
}

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("template/*")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "select_file.html", gin.H{})
	})
	router.POST("/upload", upload)
	router.StaticFS("/file", http.Dir("public"))
	router.GET("/usuarios/", handleGetUsers)
	router.PUT("/registro/", handleCreateUser)
	router.Run(":8080")
}

func upload(c *gin.Context) {

	file, header, err := c.Request.FormFile("file")
	if err != nil {

		c.String(http.StatusBadRequest, fmt.Sprintf("file err : %s", err.Error()))
		fmt.Print(err)
		return
	}
	filename := header.Filename
	out, err := os.Create("public/" + filename)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	_, err = io.Copy(out, file)
	if err != nil {
		log.Fatal(err)
	}
	filepath := "http://localhost:8080/file/" + filename
	c.JSON(http.StatusOK, gin.H{"filepath": filepath})
}

func mongoConnection() (*mongo.Client, context.Context, context.CancelFunc) {
	connectTimeout := 5

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(connectTimeout)*time.Second)

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb+srv://pelanguero:halo12345@cluster0.rjmu9.gcp.mongodb.net/slice-pdf?retryWrites=true&w=majority"))
	if err != nil {
		log.Printf("Fallo al crear el cliente: %v", err)
	}

	if err != nil {
		log.Printf("Failed to connect to cluster: %v", err)
	}

	// Force a connection to verify our connection string
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Printf("Failed to ping cluster: %v", err)
	}

	fmt.Println("Connected to MongoDB!")
	return client, ctx, cancel
}

func Create(user *Usuario) (primitive.ObjectID, error) {
	client, ctx, cancel := mongoConnection()
	defer cancel()
	defer client.Disconnect(ctx)
	user.ID = primitive.NewObjectID()
	result, err := client.Database("slice-pdf").Collection("test1").InsertOne(ctx, user)
	if err != nil {
		log.Printf("Could not create Task: %v", err)
		return primitive.NilObjectID, err
	}
	oid := result.InsertedID.(primitive.ObjectID)
	return oid, nil
}

func handleCreateUser(c *gin.Context) {
	var userr Usuario
	err := c.ShouldBindJSON(&userr)
	if err != nil {
		log.Print(err)
		log.Print(userr.Nombre)
		c.JSON(http.StatusBadRequest, gin.H{"msg": err})
		return
	}
	userr.Clave = hashpw(userr.Clave)
	//"no es coneccion es conexion"
	id, err := Create(&userr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func handleGetUsers(c *gin.Context) {
	var tasks []Usuario
	var task Usuario
	task.Nombre = "pelanguero"
	task.Correo = "pelanguero@gmail.com"

	tasks = append(tasks, task)
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func hashpw(pwd string) string {
	bytestr := []byte(pwd)
	hashh, err := bcrypt.GenerateFromPassword(bytestr, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hashh)
}

func verificarpw(hashedpw string, plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedpw), []byte(plain))
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}
