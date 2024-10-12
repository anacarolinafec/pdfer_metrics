package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Métricas Prometheus
var (
	readFileSystemEntries = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "read_file_system_entries_duration_seconds",
		Help: "Duração da leitura das entradas do sistema de arquivos",
	})
	readFile = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "read_file_duration_seconds",
		Help: "Duração da leitura do arquivo",
	})
	writeFile = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "write_file_duration_seconds",
		Help: "Duração da escrita no arquivo",
	})
	generateFile = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "generate_file_duration_seconds",
		Help: "Duração da geração do arquivo",
	})
	encryption = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "encryption_duration_seconds",
		Help: "Duração da criptografia",
	})
	decryption = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "decryption_duration_seconds",
		Help: "Duração da descriptografia",
	})
	totalRequestDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "total_request_duration_seconds",
		Help: "Duração total do request",
	})
	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_connections_total",
		Help: "Número total de conexões ativas ao servidor.",
	})
	filesCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "files_created_total",
		Help: "Número total de ficheiros criados.",
	})
	filesRead = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "files_read_total",
		Help: "Número total de ficheiros lidos.",
	})
	filesStored = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "files_stored_total",
		Help: "Quantidade de ficheiros atualmente armazenados.",
	})
	httpErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "http_errors_total",
		Help: "Número total de erros em métodos HTTP.",
	})
	activeHttpRequests = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_http_requests",
		Help: "Quantidade de métodos HTTP ativos.",
	})
	totalHttpRequests=prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "total_http_requests",
		Help: "Quantidade total de pedidos HTTP feitos.",
	})
	activeEncryptions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "active_encryptions",
		Help: "Quantidade de encriptações ativas.",
	})
)

var (
	clientReadTimes = make(map[string]time.Time)
	mu              sync.Mutex
)

func init() {
	// Registrar métricas
	prometheus.MustRegister(readFileSystemEntries)
	prometheus.MustRegister(readFile)
	prometheus.MustRegister(writeFile)
	prometheus.MustRegister(generateFile)
	prometheus.MustRegister(encryption)
	prometheus.MustRegister(decryption)
	prometheus.MustRegister(totalRequestDuration)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(filesCreated)
	prometheus.MustRegister(filesRead)
	prometheus.MustRegister(filesStored)
	prometheus.MustRegister(httpErrors)
	prometheus.MustRegister(activeHttpRequests)
	prometheus.MustRegister(totalHttpRequests)
	prometheus.MustRegister(activeEncryptions)
}

type MetricModel struct {
	Total                 int    `json:"total"`
	ReadFileSystemEntries int    `json:"readFileSystemEntries"`
	ReadFile              int    `json:"readFile"`
	WriteFile             int    `json:"writeFile"`
	GenerateFile          int    `json:"generateFile"`
	Encryption            int    `json:"encryption"`
	Decryption            int    `json:"decryption"`
	Unit                  string `json:"unit"`
}

type GetFilesResponseModel struct {
	Files   []string    `json:"files"`
	Metrics MetricModel `json:"metrics"`
}

type PostFilesRequestModel struct {
	Key      string `json:"key"`
	Length   int    `json:"length"`
	FileName string `json:"fileName"`
}

type PostFilesResponseModel struct {
	Metrics MetricModel `json:"metrics"`
}

type GetFileRequestModel struct {
	Key string `json:"key"`
}

type GetFileResponseModel struct {
	Text    string      `json:"text"`
	Metrics MetricModel `json:"metrics"`
}

func encrypt(data string, key string) (string, error) {
	byteKey := []byte(key)
	byteData := []byte(data)
	block, err := aes.NewCipher(byteKey)
	if err != nil {
		return "", err
	}
	nonce := []byte("ICA BOSSSSSS")
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	encryptedData := aesgcm.Seal(nil, nonce, byteData, nil)
	return fmt.Sprintf("%x", encryptedData), nil
}

func decrypt(encryptedData string, key string) (string, error) {
	byteKey := []byte(key)
	byteEncryptedData, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(byteKey)
	if err != nil {
		return "", err
	}
	nonce := []byte("ICA BOSSSSSS")
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	data, err := aesgcm.Open(nil, nonce, byteEncryptedData, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", string(data)), nil
}

func isClientReadRecently(clientID string, interval time.Duration) bool {
	mu.Lock()
	defer mu.Unlock()

	lastReadTime, exists := clientReadTimes[clientID]
	if !exists || time.Since(lastReadTime) > interval {
		clientReadTimes[clientID] = time.Now()
		return false
	}
	return true
}

func filesRoute(w http.ResponseWriter, r *http.Request) {
	totalStart := time.Now() // Métrica total para o request
	fs, err := ioutil.ReadDir("store")
	if err != nil {
		fmt.Println("store folder is not created")
		httpErrors.Inc()
		fmt.Println(err.Error())
		http.Error(w, "store folder is not created: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case "GET":
		var getFilesResponseModel GetFilesResponseModel
		getFilesResponseModel.Metrics.Unit = "microseconds"

		start := time.Now()
		for _, f := range fs {
			if isClientReadRecently(f.Name(), time.Second) {
				continue // Evitar leituras duplicadas
			}
			getFilesResponseModel.Files = append(getFilesResponseModel.Files, f.Name())
		}
		duration := time.Since(start).Seconds()
		getFilesResponseModel.Metrics.ReadFileSystemEntries = int(duration * 1e6) // Em microssegundos
		readFileSystemEntries.Observe(duration)

		w.WriteHeader(http.StatusOK)
		totalRequestDuration.Observe(time.Since(totalStart).Seconds())
		json.NewEncoder(w).Encode(getFilesResponseModel)

	case "POST":
		var postFilesRequestModel PostFilesRequestModel
		err := json.NewDecoder(r.Body).Decode(&postFilesRequestModel)
		if err != io.EOF && err != nil {
			fmt.Println("Failed to parse body")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to parse body: "+err.Error(), http.StatusBadRequest)
			return
		}

		if len(postFilesRequestModel.Key) != 16 {
			fmt.Println("Key must be 16 bytes length")
			httpErrors.Inc()
			http.Error(w, "Key must be 16 bytes length", http.StatusBadRequest)
			return
		}

		var postFilesResponseModel PostFilesResponseModel
		postFilesResponseModel.Metrics.Unit = "microseconds"

		start := time.Now()
		var fileContent string
		for i := 0; i < postFilesRequestModel.Length; i++ {
			fileContent = fileContent + "a"
		}
		duration := time.Since(start).Seconds()
		postFilesResponseModel.Metrics.GenerateFile = int(duration * 1e6)
		generateFile.Observe(duration)

		start = time.Now()
		encriptedFileContent, err := encrypt(fileContent, postFilesRequestModel.Key)
		duration = time.Since(start).Seconds()
		postFilesResponseModel.Metrics.Encryption = int(duration * 1e6)
		encryption.Observe(duration)
		if err != nil {
			fmt.Println("Failed to encrypt data")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to encrypt data: "+err.Error(), http.StatusBadRequest)
			return
		}

		start = time.Now()
		err = os.WriteFile("store/"+postFilesRequestModel.FileName, []byte(encriptedFileContent), 0644)
		duration = time.Since(start).Seconds()
		postFilesResponseModel.Metrics.WriteFile = int(duration * 1e6)
		writeFile.Observe(duration)
		if err != nil {
			fmt.Println("Failed to write to disk")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to write to disk: "+err.Error(), http.StatusInternalServerError)
			return
		}

		filesCreated.Inc() // Incrementa o número de ficheiros criados
		filesStored.Inc()  // Incrementa o número de ficheiros armazenados

		w.WriteHeader(http.StatusCreated)
		totalRequestDuration.Observe(time.Since(totalStart).Seconds())
		json.NewEncoder(w).Encode(postFilesResponseModel)

	default:
		httpErrors.Inc()
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func fileRoute(w http.ResponseWriter, r *http.Request) {
	totalStart := time.Now() // Métrica total para o request
	_, err := ioutil.ReadDir("store")
	if err != nil {
		fmt.Println("store folder is not created")
		httpErrors.Inc()
		fmt.Println(err.Error())
		http.Error(w, "store folder is not created", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	fileId, ok := vars["fileId"]
	if !ok {
		fmt.Println("id is missing in parameters")
		httpErrors.Inc()
		http.Error(w, "id is missing in parameters", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		var getFileRequestModel GetFileRequestModel
		err := json.NewDecoder(r.Body).Decode(&getFileRequestModel)
		if err != io.EOF && err != nil {
			fmt.Println("Failed to parse body")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to parse body", http.StatusBadRequest)
			return
		}

		if len(getFileRequestModel.Key) != 16 {
			fmt.Println("Key must be 16 bytes length")
			httpErrors.Inc()
			http.Error(w, "Key must be 16 bytes length", http.StatusBadRequest)
			return
		}

		var getFileResponseModel GetFileResponseModel
		getFileResponseModel.Metrics.Unit = "microseconds"

		start := time.Now()
		encryptedFileContent, err := os.ReadFile("store/" + fileId)
		duration := time.Since(start).Seconds()
		getFileResponseModel.Metrics.ReadFile = int(duration * 1e6) // Em microssegundos
		readFile.Observe(duration)
		if err != nil {
			fmt.Println("Failed to get file")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to get file", http.StatusInternalServerError)
			return
		}

		filesRead.Inc() // Incrementa o número de ficheiros lidos

		start = time.Now()
		fileContent, err := decrypt(string(encryptedFileContent), getFileRequestModel.Key)
		duration = time.Since(start).Seconds()
		getFileResponseModel.Metrics.Decryption = int(duration * 1e6)
		decryption.Observe(duration)
		if err != nil {
			fmt.Println("Failed to decrypt data")
			httpErrors.Inc()
			fmt.Println(err.Error())
			http.Error(w, "Failed to decrypt data: "+err.Error(), http.StatusBadRequest)
			return
		}

		getFileResponseModel.Text = fileContent

		w.WriteHeader(http.StatusOK)
		totalRequestDuration.Observe(time.Since(totalStart).Seconds())
		json.NewEncoder(w).Encode(getFileResponseModel)

	default:
		httpErrors.Inc()
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// MetricsMiddleware is a middleware that collects metrics for each request.
func MetricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()        // Incrementa conexões ativas no início da requisição
		defer activeConnections.Dec()  // Garante que as conexões ativas são decrementadas no final da requisição
		activeHttpRequests.Inc()       // Incrementa pedidos HTTP ativos
		defer activeHttpRequests.Dec()
		totalHttpRequests.Inc() // Garante que são decrementados no final

        // Start the timer to measure total request duration
        //start := time.Now()

        // Execute the next handler in the chain
        next.ServeHTTP(w, r)

        // Record the total request duration once the handler has finished
        //duration := time.Since(start).Seconds()
        //totalRequestDuration.Observe(duration)
    })
}

func main() {
	r := mux.NewRouter()

	r.Use(MetricsMiddleware)

    // Define your routes
    r.HandleFunc("/files", filesRoute)
    r.HandleFunc("/files/{fileId}", fileRoute)

	// Rota para expor métricas do Prometheus
	r.Handle("/metrics", promhttp.Handler())

	port := 8080
	http.ListenAndServe(fmt.Sprintf(":%d", port), r)
}
