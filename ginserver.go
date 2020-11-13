package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	Correo string `json:"correo"`
	jwt.StandardClaims
}

type Credenciales struct {
	Clave  string
	Correo string
}

type Usuario struct {
	ID     primitive.ObjectID
	Nombre string
	Correo string
	Foto   string
	Clave  string
}
type Libro struct {
	ID      primitive.ObjectID
	Usuario string
	Archivo string
}
type Seccion struct {
	ID       primitive.ObjectID
	Libro    primitive.ObjectID
	Usuario  primitive.ObjectID
	PaginaIn int
	PaginaFi int
	Paginas  []primitive.ObjectID
}
type Pagina struct {
	ID      primitive.ObjectID
	Usuario primitive.ObjectID //correo
	Libro   primitive.ObjectID
	Seccion primitive.ObjectID
	Texto   string
	Pagina  int
}

var jwtkey = []byte("clave secreta xd")

func main() {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "PATCH"},
		AllowHeaders:     []string{"Origin", "X-Requested-With", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		MaxAge: 12 * time.Hour,
	}))
	router.LoadHTMLGlob("template/*")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "select_file.html", gin.H{})
	})
	router.POST("/upload", upload)
	router.StaticFS("/file", http.Dir("public"))
	router.GET("/usuarios/", handleGetUsers)
	router.PUT("/registro/", handleCreateUser)
	router.PUT("/iniciosesion", iniciosesion)
	router.Run(":8080")
}

func iniciosesion(c *gin.Context) {

	var creds Credenciales
	var testt Usuario
	err := c.ShouldBindJSON(&creds)
	if err != nil {
		log.Print(err)
		log.Print(creds.Correo)
		c.JSON(http.StatusLocked, gin.H{"msg": err})
		return
	}
	filtro := bson.M{"correo": creds.Correo}
	client, ctx, cancel := mongoConnection()
	defer cancel()
	defer client.Disconnect(ctx)

	errorr := client.Database("slice-pdf").Collection("usuarios").FindOne(context.TODO(), filtro).Decode(&testt)
	if errorr != nil {
		log.Println(errorr)
	}
	if testt.Correo == creds.Correo && verificarpw(testt.Clave, creds.Clave) {
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			Correo: creds.Correo,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, errr := token.SignedString(jwtkey)
		if errr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": errr})
		}
		c.JSON(http.StatusAccepted, gin.H{"Name": "token", "Value": tokenString, "Expira": expirationTime})
	} else {
		corsmiddle(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales no validas"})
	}

}

//middleware que maneja los cors
func corsmiddle(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
	c.Header("Access-Control-Allow-Methods", "PUT, POST, DELETE, GET")
}

//procesa multipart/form-data para la subida de archivos con un campo adicional en el header "token"
func upload(c *gin.Context) {
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)
	corsmiddle(c)
	if 0 == statuss {
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
		filepath := "http://localhost:8080/public/" + filename
		agregarlibro(filename, claim.Correo)
		c.JSON(http.StatusOK, gin.H{"Libro": "exito", "ruta": filepath})
	} else if statuss == 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado para subir archivos"})
		return
	} else if statuss == -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
		return
	} else if statuss == 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado para subir archivos, token no valido"})
		return
	}

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

func Create(user *Usuario) (primitive.ObjectID, bool, error) {
	var oid primitive.ObjectID
	var existe bool
	client, ctx, cancel := mongoConnection()
	filtro := bson.M{"correo": user.Correo}
	var testt Usuario
	defer cancel()
	defer client.Disconnect(ctx)
	user.ID = primitive.NewObjectID()
	errorr := client.Database("slice-pdf").Collection("usuarios").FindOne(context.TODO(), filtro).Decode(&testt)
	if errorr != nil {
		log.Println(errorr)
	}
	if testt.Correo != user.Correo {
		result, err := client.Database("slice-pdf").Collection("usuarios").InsertOne(ctx, user)
		if err != nil {
			log.Printf("No se pudo agregar el usuario: %v", err)
			return primitive.NilObjectID, err, false
		}
		oid = result.InsertedID.(primitive.ObjectID)
		existe = false
	} else {
		log.Println("El Usuario ya existe")
		existe = true
	}

	return oid, nil, existe
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
	id, insertod, err := Create(&userr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err})
		return
	}
	if insertod {
		c.JSON(http.StatusOK, gin.H{"error": "El Usuario ya existe"})
	} else {
		c.JSON(http.StatusOK, gin.H{"id": id})
	}
	corsmiddle(c)
}

//funcion temporal
func handleGetUsers(c *gin.Context) {
	var tasks []Usuario
	var task Usuario
	task.Nombre = "pelanguero"
	task.Correo = "pelanguero@gmail.com"

	tasks = append(tasks, task)
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

//es para no guardar el pw plano
func hashpw(pwd string) string {
	bytestr := []byte(pwd)
	hashh, err := bcrypt.GenerateFromPassword(bytestr, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hashh)
}

//verifica el pw con hash y el posible pw plano
func verificarpw(hashedpw string, plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedpw), []byte(plain))
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

//verifica el token (jwt) returna 0 si el token esta bien, 1 si la firma es invalida, 2 si el token no es valido y -1 si no se hizo la peticion de manera correcta
func verificarjwt(jjwt string, clai *Claims) int {
	tkn, errorr := jwt.ParseWithClaims(jjwt, clai, func(token *jwt.Token) (interface{}, error) {
		return jwtkey, nil
	})

	if errorr != nil {
		if errorr == jwt.ErrSignatureInvalid {
			return 1
		}
		return -1
	}
	if !tkn.Valid {
		return 2
	}

	return 0
}

//agrega un libro con el usuario y la ruta dadas
func agregarlibro(rutaArchivo string, usuarioo string) (bool, primitive.ObjectID) {
	var oid primitive.ObjectID
	client, ctx, cancel := mongoConnection()
	var testt Libro
	fmt.Println(rutaArchivo)
	fmt.Println(usuarioo)
	testt.Archivo = rutaArchivo
	testt.Usuario = usuarioo
	testt.ID = primitive.NewObjectID()
	defer cancel()
	defer client.Disconnect(ctx)
	result, err := client.Database("slice-pdf").Collection("libros").InsertOne(ctx, testt)
	if err != nil {
		log.Printf("No se pudo agregar el Libro: %v", err)
		return false, oid
	}
	oid = result.InsertedID.(primitive.ObjectID)
	return true, oid
}
