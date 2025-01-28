package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/SmallSonxdd/chirpy/internal/auth"
	"github.com/SmallSonxdd/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	platform       string
	secret         string
	polka_key      string
}

type ErrorResponse struct {
	Error string `json:"error"`
}

const metricsPage string = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

var BadWrods = []string{"kerfuffle", "sharbert", "fornax"}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(metricsPage, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(403)
		return
	}
	cfg.queries.Reset(r.Context())
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))

}

func (cfg *apiConfig) validateHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := struct {
		Body string `json:"body"`
	}{}
	err := decoder.Decode(&params)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		fmt.Printf("Decoding err: %s", err)
		res, err := json.Marshal(ErrorResponse{Error: "Something went wrong"})
		if err != nil {
			fmt.Printf("Followed by encoding error err: %s", err)
			return
		}
		w.WriteHeader(400)
		w.Write(res)
		return
	}
	if len(params.Body) > 140 {
		res, err := json.Marshal(ErrorResponse{Error: "Chirp is too long"})
		if err != nil {
			fmt.Printf("Encoding error during checking length: %s", err)
			return
		}
		w.WriteHeader(400)
		w.Write(res)
		return
	}
	paramStruct2 := struct {
		Body string `json:"cleaned_body"`
	}{
		Body: cleanString(params.Body),
	}

	res, err := json.Marshal(paramStruct2)
	if err != nil {
		fmt.Printf("Encoding error during validating: %s", err)
		return
	}
	w.WriteHeader(200)
	w.Write(res)

}

func (cfg *apiConfig) handlerCreateUsers(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("Decoder error:")
		fmt.Println(err)
		return
	}
	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println("Hashing password error:")
		fmt.Println(err)
		return
	}
	createUserParams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	}
	user, err := cfg.queries.CreateUser(r.Context(), createUserParams)
	if err != nil {
		fmt.Println("CreateUser method error:")
		fmt.Println(err)
	}
	resParams := struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		ChirpyRed bool      `json:"is_chirpy_red"`
	}{
		Id:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		ChirpyRed: user.IsChirpyRed.Bool,
	}
	res, err := json.Marshal(resParams)
	if err != nil {
		fmt.Println("Marshalling response parameters error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(res)

}

func (cfg *apiConfig) handlerAddChirp(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := struct {
		Body string `json:"body"`
	}{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("Decoder error:")
		fmt.Println(err)
		return
	}
	authorization, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Failed to get bearer token", http.StatusUnauthorized)
		return
	}
	validation, err := auth.ValidateJWT(authorization, cfg.secret)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid JWT", http.StatusUnauthorized)
		return
	}
	if validation == uuid.Nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		return
	}
	if len(params.Body) > 140 {
		res, err := json.Marshal(ErrorResponse{Error: "Chirp is too long"})
		if err != nil {
			fmt.Printf("Encoding error during checking length: %s", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(res)
		return
	}
	chirp, err := cfg.queries.CreateChirp(r.Context(), database.CreateChirpParams{Body: params.Body, UserID: validation})
	if err != nil {
		fmt.Println("Chirp database creation error:")
		fmt.Println(err)
		return
	}
	resParams := struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}{
		Id:         chirp.ID,
		Created_at: chirp.CreatedAt,
		Updated_at: chirp.UpdatedAt,
		Body:       chirp.Body,
		User_id:    chirp.UserID,
	}
	res, err := json.Marshal(resParams)
	if err != nil {
		fmt.Println("Marshalling response parameters error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(res)

}

func (cfg *apiConfig) handlerGetChrisp(w http.ResponseWriter, r *http.Request) {
	var chirps []database.Chirp
	var err error
	author := r.URL.Query().Get("author_id")
	sortQ := r.URL.Query().Get("sort")

	if author == "" {
		chirps, err = cfg.queries.GetChirps(r.Context())
		if err != nil {
			fmt.Println("Database query GetChrips error:")
			fmt.Println(err)
			return
		}
	} else {
		u, err := uuid.Parse(author)
		if err != nil {
			fmt.Println("Parsing string to uuid error:")
			fmt.Println(err)
			return
		}
		chirps, err = cfg.queries.GetChirpsForAuthor(r.Context(), u)
		if err != nil {
			fmt.Println("Database query GetChrips error:")
			fmt.Println(err)
			return
		}
	}
	resParams := []database.Chirp{}

	for _, chirp := range chirps {
		resParams = append(resParams, database.Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	}
	if sortQ == "desc" {
		sort.Slice(resParams, func(i, j int) bool { return resParams[i].CreatedAt.After(resParams[j].CreatedAt) })
	}

	res, err := json.Marshal(resParams)
	if err != nil {
		fmt.Println("Marshaling slice of chirps error:")
		fmt.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)

}

func (cfg *apiConfig) handlerGetSingleChirp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		http.Error(w, "Chirp ID is required", http.StatusBadRequest)
		return
	}
	u, err := uuid.Parse(chirpID)
	if err != nil {
		fmt.Println("Parsing string to uuid error:")
		fmt.Println(err)
		return
	}
	resChirp, err := cfg.queries.GetSingleChirp(r.Context(), u)
	if err != nil {
		w.WriteHeader(404)
		fmt.Println("Grabbing chirp from database error:")
		fmt.Println(err)
		return
	}
	res, err := json.Marshal(struct {
		Id         uuid.UUID `json:"id"`
		Created_at time.Time `json:"created_at"`
		Updated_at time.Time `json:"updated_at"`
		Body       string    `json:"body"`
		User_id    uuid.UUID `json:"user_id"`
	}{
		Id:         resChirp.ID,
		Created_at: resChirp.CreatedAt,
		Updated_at: resChirp.UpdatedAt,
		Body:       resChirp.Body,
		User_id:    resChirp.UserID,
	})
	if err != nil {
		fmt.Println("Marshaling chirp error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)

}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}{}
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Println("Decoder error:")
		fmt.Println(err)
		return
	}
	user, err := cfg.queries.GetUserPasswordByEmail(r.Context(), params.Email)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}
	compareErr := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if compareErr != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}
	token, err := auth.MakeJWT(user.ID, cfg.secret, time.Hour)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Making token failure"))
		return
	}
	rToken, err := auth.MakeRefreshToken()
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Creating refresh token failure"))
		return
	}
	err = cfg.queries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{Token: rToken, UserID: user.ID})
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Inserting refresh token failure"))
		return
	}
	res, err := json.Marshal(struct {
		Id            uuid.UUID `json:"id"`
		Created_at    time.Time `json:"created_at"`
		Updated_at    time.Time `json:"updated_at"`
		Email         string    `json:"email"`
		Token         string    `json:"token"`
		Refresh_token string    `json:"refresh_token"`
		Chirpy_red    bool      `json:"is_chirpy_red"`
	}{
		Id:            user.ID,
		Created_at:    user.CreatedAt,
		Updated_at:    user.UpdatedAt,
		Email:         user.Email,
		Token:         token,
		Refresh_token: rToken,
		Chirpy_red:    user.IsChirpyRed.Bool,
	})
	if err != nil {
		fmt.Println("Marshaling error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)

}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	authorization, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Failed to get bearer token", http.StatusUnauthorized)
		return
	}
	expirationTime, err := cfg.queries.GetTokenExistenceAndValidity(r.Context(), authorization)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Println("No token found error:")
		fmt.Println(err)
		return
	} else if err != nil {
		fmt.Println("Another getting refresh token error:")
		fmt.Println(err)
		return
	}
	if expirationTime.RevokedAt.Valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Println("Token has been revoked")
		return
	}

	currentTime := time.Now()

	if expirationTime.ExpiresAt.Before(currentTime) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Printf("expiration time has expired for token: %s\n", authorization)
		return
	}
	user, err := cfg.queries.GetUserForRefreshToken(r.Context(), authorization)
	if err != nil {
		fmt.Println("Getting user from DB error:")
		fmt.Println(err)
		return
	}
	token, err := auth.MakeJWT(user, cfg.secret, time.Hour)
	if err != nil {
		fmt.Println("Making JWT error:")
		fmt.Println(err)
		return
	}
	res, err := json.Marshal(struct {
		Token string `json:"token"`
	}{
		Token: token,
	})
	if err != nil {
		fmt.Println("Marshaling error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	authorization, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Failed to get bearer token", http.StatusUnauthorized)
		return
	}
	currentTime := time.Now()
	err = cfg.queries.SetRevocationTimestampForRefreshToken(r.Context(), database.SetRevocationTimestampForRefreshTokenParams{
		Token:     authorization,
		RevokedAt: sql.NullTime{Time: currentTime, Valid: true},
	})
	if err != nil {
		fmt.Println("Setting revoked_at column to current time error:")
		fmt.Println(err)
		return
	}
	w.WriteHeader(204)

}

func (cfg *apiConfig) handlerUpdateEmailAndPassword(w http.ResponseWriter, r *http.Request) {
	authorization, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		fmt.Println("Getting authorization token from header error:")
		fmt.Println(err)
		return
	}

	user, err := auth.ValidateJWT(authorization, cfg.secret)
	if err != nil {
		w.WriteHeader(401)
		fmt.Println("Validating authorization token error:")
		fmt.Println(err)
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}
	err = decoder.Decode(&params)
	if err != nil {
		fmt.Println("Decoding request body error:")
		fmt.Println(err)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		fmt.Println("Hashing password error:")
		fmt.Println(err)
		return
	}
	err = cfg.queries.UpdateEmailAndPasswordForUser(r.Context(), database.UpdateEmailAndPasswordForUserParams{
		ID:             user,
		Email:          params.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		fmt.Println("Updating email and password error:")
		fmt.Println(err)
		return
	}
	userStruct, err := cfg.queries.GetUserPasswordByEmail(r.Context(), params.Email)
	if err != nil {
		fmt.Println("Getting full user from db error:")
		fmt.Println(err)
		return
	}

	resParams := struct {
		Id        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		ChirpyRed bool      `json:"is_chirpy_red"`
	}{
		Id:        userStruct.ID,
		CreatedAt: userStruct.CreatedAt,
		UpdatedAt: userStruct.UpdatedAt,
		Email:     userStruct.Email,
		ChirpyRed: userStruct.IsChirpyRed.Bool,
	}
	res, err := json.Marshal(resParams)
	if err != nil {
		fmt.Println("Marshalling response parameters error:")
		fmt.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(res)

}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	authorization, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		fmt.Println("Getting authorization token from header error:")
		fmt.Println(err)
		return
	}

	user, err := auth.ValidateJWT(authorization, cfg.secret)
	if err != nil {
		w.WriteHeader(401)
		fmt.Println("Validating authorization token error:")
		fmt.Println(err)
		return
	}

	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		http.Error(w, "Chirp ID is required", http.StatusBadRequest)
		return
	}
	u, err := uuid.Parse(chirpID)
	if err != nil {
		fmt.Println("Parsing string to uuid error:")
		fmt.Println(err)
		return
	}

	chirp, err := cfg.queries.GetSingleChirp(r.Context(), u)
	if user != chirp.UserID {
		w.WriteHeader(403)
		fmt.Println("Unauthorized user")
		return
	}
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Println("No token found error:")
		fmt.Println(err)
		return
	} else if err != nil {
		fmt.Println("Another getting chirp error:")
		fmt.Println(err)
		return
	}
	err = cfg.queries.DeleteSingleChirpForChirpID(r.Context(), u)
	if err != nil {
		fmt.Println("Deleting chirp from db error:")
		fmt.Println(err)
		return
	}
	w.WriteHeader(204)

}

func (cfg *apiConfig) handlerUpgradeChirpyRed(w http.ResponseWriter, r *http.Request) {
	authorization, err := auth.GetAPIKey(r.Header)
	if err != nil {
		w.WriteHeader(401)
		fmt.Println("Getting API key from header error:")
		fmt.Println(err)
		return
	}
	if cfg.polka_key != authorization {
		w.WriteHeader(401)
		fmt.Println("Mismatched polka API key")
		return
	}

	decoder := json.NewDecoder(r.Body)
	params := struct {
		Event string `json:"event"`
		Data  struct {
			User_id string `json:"user_id"`
		} `json:"data"`
	}{}
	err = decoder.Decode(&params)
	if err != nil {
		fmt.Println("Decoding request body error:")
		fmt.Println(err)
		return
	}
	fmt.Printf("Received user_id: %s\n", params.Data.User_id)
	if params.Event != "user.upgraded" {
		w.WriteHeader(204)
		fmt.Println("Anotther event other than upgrade")
		return
	}
	u, err := uuid.Parse(params.Data.User_id)
	if err != nil {
		fmt.Println("Parsing string to uuid error:")
		fmt.Println(err)
		return
	}
	err = cfg.queries.UpdateToChirpyRed(r.Context(), u)
	if err == sql.ErrNoRows {
		w.WriteHeader(404)
		fmt.Println("User not found")
		return
	} else if err != nil {
		fmt.Println("Another error to updating user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(204)
	w.Write([]byte{})

}

func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func cleanString(s string) string {
	split := strings.Split(s, " ")
	replaced := []string{}
	for _, item_of_split := range split {
		checkerForBadWords := false
		for _, item_of_badWords := range BadWrods {
			if strings.ToLower(item_of_split) == item_of_badWords {
				checkerForBadWords = true
			}
		}
		if !checkerForBadWords {
			replaced = append(replaced, item_of_split)
		} else {
			replaced = append(replaced, "****")
		}
	}

	return strings.Join(replaced, " ")
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	polka_key := os.Getenv("POLKA_KEY")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
		return
	}
	dbQueries := database.New(db)

	apiCfg := apiConfig{fileserverHits: atomic.Int32{},
		queries:   dbQueries,
		platform:  platform,
		secret:    secret,
		polka_key: polka_key,
	}
	fmt.Println("Loaded secret:", apiCfg.secret)

	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.handlerAddChirp)
	mux.HandleFunc("POST /api/users", apiCfg.handlerCreateUsers)
	mux.HandleFunc("GET /api/chirps", apiCfg.handlerGetChrisp)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handlerGetSingleChirp)
	mux.HandleFunc("POST /api/login", apiCfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", apiCfg.handlerUpdateEmailAndPassword)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.handlerDeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.handlerUpgradeChirpyRed)
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()

}
