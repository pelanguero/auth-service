package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
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
	Imagen  string
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
type CheatSheet struct {
	ID      primitive.ObjectID
	Usuario string
	Titulo  string
}
type Cheat struct {
	ID         primitive.ObjectID
	Titulo     string
	Cheatsheet primitive.ObjectID
	Contenido  string
}

var jwtkey = []byte("clave secreta xd")

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error al cargar .env")
	}
	jwtkey = []byte(os.Getenv("JWT_KEY"))
	router := gin.Default()
	//
	router.Use(CORSMiddleware())
	router.LoadHTMLGlob("template/*")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "select_file.html", gin.H{})
	})
	router.POST("/upload", upload)
	router.POST("/addCheatSheet", crearCheatSheet)
	router.POST("/addCheat", crearCheat)
	router.Static("/images", "./public/images")
	router.StaticFS("/file", http.Dir("public"))
	router.OPTIONS("/file", opciones)
	router.GET("/usuarios/", handleGetUsers)
	router.GET("/inicio", paginicio)
	router.GET("/cheatsheets", consultaCheatSheets)
	router.GET("/cheats", consultaCheats)
	router.PUT("/registro/", handleCreateUser)
	router.PUT("/iniciosesion", iniciosesion)
	router.OPTIONS("/iniciosesion", opciones)
	router.OPTIONS("/inicio", opciones)
	router.OPTIONS("/upload", opciones)
	//router.Use(cors.Default())

	router.Run(":8080")
}
func opciones(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Headers", "access-control-allow-origin, access-control-allow-headers,access-control-allow-origin")
	c.JSON(http.StatusOK, gin.H{"opciones": "des"})
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control,token, X-Requested-With,access-control-allow-origin")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
func consultaCheats(c *gin.Context) {
	var chsh CheatSheet
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)
	erorr := c.ShouldBindJSON(&chsh)
	if erorr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": erorr})
		return
	} else {

		if 0 == statuss {
			filtro := bson.M{"CheatSheet": chsh.ID}
			findOps := options.Find()
			//findOps.SetLimit(10)
			client, ctx, cancel := mongoConnection()
			defer cancel()
			defer client.Disconnect(ctx)
			var consulta []*CheatSheet
			con, err := client.Database("slice-pdf").Collection("cheats").Find(context.TODO(), filtro, findOps)
			if err != nil {
				log.Fatal(err)
			}
			for con.Next(context.TODO()) {
				var s CheatSheet
				err := con.Decode(&s)
				if err != nil {
					log.Fatal(err)
				}
				consulta = append(consulta, &s)
			}

			if err := con.Err(); err != nil {
				log.Fatal(err)
			}

			con.Close(context.TODO())
			c.JSON(http.StatusOK, gin.H{"CheatSheets": consulta})

		} else if statuss == 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado"})
			return
		} else if statuss == -1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
			return
		} else if statuss == 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado, token no valido"})
			return
		}
	}

}

func consultaCheatSheets(c *gin.Context) {
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)

	if 0 == statuss {
		filtro := bson.M{"usuario": claim.Correo}
		findOps := options.Find()
		//findOps.SetLimit(10)
		client, ctx, cancel := mongoConnection()
		defer cancel()
		defer client.Disconnect(ctx)
		var consulta []*CheatSheet
		con, err := client.Database("slice-pdf").Collection("cheatsheets").Find(context.TODO(), filtro, findOps)
		if err != nil {
			log.Fatal(err)
		}
		for con.Next(context.TODO()) {
			var s CheatSheet
			err := con.Decode(&s)
			if err != nil {
				log.Fatal(err)
			}
			consulta = append(consulta, &s)
		}

		if err := con.Err(); err != nil {
			log.Fatal(err)
		}

		con.Close(context.TODO())
		c.JSON(http.StatusOK, gin.H{"CheatSheets": consulta})

	} else if statuss == 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado"})
		return
	} else if statuss == -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
		return
	} else if statuss == 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado, token no valido"})
		return
	}
}

//crea una cheatsheet en la base de datos
func crearCheatSheet(c *gin.Context) {
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)
	if 0 == statuss {
		//filtro := bson.M{"usuario": claim.Correo}
		//findOps := options.Find()
		//findOps.SetLimit(10)
		var chsh CheatSheet
		erorr := c.ShouldBindJSON(&chsh)
		if erorr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": erorr})
			return
		}
		chsh.ID = primitive.NewObjectID()
		chsh.Usuario = claim.Correo
		client, ctx, cancel := mongoConnection()
		defer cancel()
		defer client.Disconnect(ctx)
		con, err := client.Database("slice-pdf").Collection("cheatsheets").InsertOne(ctx, chsh)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Fallo al crear la cheatsheet"})
		} else {
			c.JSON(http.StatusOK, gin.H{"CheatSheet": chsh.ID, "resultado": con})
		}

	} else if statuss == 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado"})
		return
	} else if statuss == -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
		return
	} else if statuss == 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado, token no valido"})
		return
	}
}

//crea un cheat
func crearCheat(c *gin.Context) {
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)

	if 0 == statuss {
		var cheat Cheat
		erorr := c.ShouldBindJSON(&cheat)
		if erorr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": erorr})
			return
		}
		cheat.ID = primitive.NewObjectID()
		client, ctx, cancel := mongoConnection()
		defer cancel()
		defer client.Disconnect(ctx)
		con, err := client.Database("slice-pdf").Collection("cheats").InsertOne(ctx, cheat)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Fallo al crear el cheat"})
		} else {
			c.JSON(http.StatusOK, gin.H{"CheatSheet": cheat.ID, "resultado": con})
		}

	} else if statuss == 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado"})
		return
	} else if statuss == -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
		return
	} else if statuss == 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado, token no valido"})
		return
	}
}

//retorna los libros asociados al usuario
func paginicio(c *gin.Context) {

	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)
	if 0 == statuss {
		filtro := bson.M{"usuario": claim.Correo}
		findOps := options.Find()
		findOps.SetLimit(10)
		client, ctx, cancel := mongoConnection()
		defer cancel()
		defer client.Disconnect(ctx)
		var consulta []*Libro
		con, err := client.Database("slice-pdf").Collection("libros").Find(context.TODO(), filtro, findOps)
		if err != nil {
			log.Fatal(err)
		}
		for con.Next(context.TODO()) {
			var s Libro
			err := con.Decode(&s)
			if err != nil {
				log.Fatal(err)
			}
			consulta = append(consulta, &s)
		}

		if err := con.Err(); err != nil {
			log.Fatal(err)
		}

		con.Close(context.TODO())
		c.JSON(http.StatusOK, gin.H{"libros": consulta})

	} else if statuss == 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado"})
		return
	} else if statuss == -1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Peticion invalida"})
		return
	} else if statuss == 2 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No estas Autorizado, token no valido"})
		return
	}

}

//recibe las credenciales las comprueba y retorna el token si es correcta
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

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales no validas"})
	}

}

//procesa multipart/form-data para la subida de archivos con un campo adicional en el header "token"
func upload(c *gin.Context) {
	claim := &Claims{}
	statuss := verificarjwt(c.Request.Header.Get("token"), claim)
	if 0 == statuss {
		file, header, err := c.Request.FormFile("myFile")
		if err != nil {

			c.String(http.StatusBadRequest, fmt.Sprintf("file err : %s", err.Error()))
			fmt.Println(err)
			return
		}

		filename := strings.ReplaceAll(header.Filename, " ", "")
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
		creartumb("./public/"+filename, filename)
		agregarlibro(filename, claim.Correo, "http://localhost:8080/images/"+filename+".png")
		//pendiente agregar variable o variable de entorno para las rutas de archivos locales
		subiraBucket("general-developing-brutality", "./public/"+filename)
		subiraBucket("general-developing-brutality", "./public/"+filename+".png")
		c.JSON(http.StatusOK, gin.H{"Libro": filename, "ruta": filepath})
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
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error al cargar .env")
	}

	connectTimeout := 5

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(connectTimeout)*time.Second)

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_CONNECTION")))
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

func Create(user *Usuario) (primitive.ObjectID, error, bool) {
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
	id, err, insertod := Create(&userr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err})
		return
	}
	if insertod {
		c.JSON(http.StatusOK, gin.H{"error": "El Usuario ya existe"})
	} else {
		c.JSON(http.StatusOK, gin.H{"id": id})
	}

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
		fmt.Println(errorr.Error())
		fmt.Println("Este es el token" + jjwt)
		return -1
	}
	if !tkn.Valid {
		return 2
	}

	return 0
}

//agrega un libro con el usuario y la ruta dadas
func agregarlibro(rutaArchivo string, usuarioo string, imagenn string) (bool, primitive.ObjectID) {
	var oid primitive.ObjectID
	client, ctx, cancel := mongoConnection()
	var testt Libro
	fmt.Println(rutaArchivo)
	fmt.Println(usuarioo)
	testt.Archivo = rutaArchivo
	testt.Usuario = usuarioo
	testt.Imagen = imagenn
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

//crea la miniatura del libro a partir de la primera pagina
func creartumb(ruta_pdf string, nombre_pdf string) {
	cmd := exec.Command("python", "tumb.py", ruta_pdf, "./public/", nombre_pdf)
	var out bytes.Buffer
	fmt.Println("intento crear la miniatura")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())

}

//muestra los errores del sdk de aws
func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

//subir a bucket "general-developing-brutality"
func subiraBucket(buckett string, file string) {
	verb := true
	archivo, err := os.Open(file)
	if err != nil {
		exitErrorf("Incapaz de abrir el archivo %q, %v", err)
	}
	defer archivo.Close()

	creds := credentials.NewStaticCredentials(os.Getenv("AWS_ID"), os.Getenv("AWS_SECRET"), "")
	// Retrieve the credentials value
	credValue, err := creds.Get()
	if err != nil {
		if credValue.AccessKeyID == "" {

		}
		fmt.Println(err)
	}

	session := session.Must(session.NewSession(&aws.Config{
		Region:                        aws.String("us-east-1"),
		CredentialsChainVerboseErrors: &verb,
		Credentials:                   creds,
	}))

	uploader := s3manager.NewUploader(session)

	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(buckett),
		Key:    aws.String(file),
		Body:   archivo,
	})

	if err != nil {
		exitErrorf("Incapaz de subir el archivo %q to %q, %v", file, buckett, err)
	}

	fmt.Printf("Archivo subido  %q to %q\n", file, buckett)
}

func descargaMulti() {

}
