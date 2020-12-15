/*
Copyright © 2020 amit dixit

*/
package cmd

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

/*
 * Token Structure.
 */

type AuthToken struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

/*
* counter for bytes transfer
 */
type WriteCounter struct {
	Total uint64
}

/*
*  Structure of the received container image manifest.
 */
type ManifestReceived struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int    `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

/*
* Layout of the manifest file in the image layers
 */
type ManifestWriteForDocker struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

/*
* Image layer manifest file written with the image layers.
 */
type manifestJsonFileImage struct {
	manifestJsonFileImage []ManifestWriteForDocker
}

/*
* sub-command : Pull to pull iage layers from docker registry.
 */
var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "pulls a docker image  from artifactory docker repository",
	Long:  `pulls a docker image  from artifactory docker repository.  `,
	Run: func(cmd *cobra.Command, args []string) {
		image, _ := cmd.Flags().GetString("image")
		username, _ := cmd.Flags().GetString("username")
		if username == "" {
			username = viper.GetString("username")
		}
		password, _ := cmd.Flags().GetString("password")
		if password == "" {
			decodedpassword, _ := base64.StdEncoding.DecodeString(viper.GetString("password"))
			password = string(decodedpassword)
		}

		tag, _ := cmd.Flags().GetString("tag")
		if tag == "" {
			tag = "latest"
			fmt.Println("No tag provided, Using latest tag")
		}

		fmt.Printf("Pulling image %s:%s \n", image, tag)
		splitimage := strings.Split(image, "/")

		imageRepository := splitimage[0]
		imagename := strings.Join(splitimage[1:], "/")

		if len(imageRepository) == 0 {
			imageRepository = "registry-1.docker.io"
		}
		// http client
		client := &http.Client{}
		// get authorization token from artifactory.
		req, _ := http.NewRequest("GET", "https://artifactory.test.com/v2/token", nil)

		req.Header.Add("Authorization", "Basic "+basicAuth(username, password))

		resp, err := client.Do(req)
		HandleError(err, "Error retrieving token for image download")
		defer resp.Body.Close()
		var authtoken AuthToken
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&authtoken)
		HandleError(err, "Error decoding auth token")
		// now we have token in auth struct.

		// Pull manifest file  for the image.

		manifesturl := fmt.Sprintf("https://%s/v2/%s/manifests/%s", imageRepository, imagename, tag)
		manifestreq, _ := http.NewRequest("GET", manifesturl, nil)
		manifestreq.Header.Add("Authorization", "Bearer "+authtoken.Token)
		manifestreq.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v2+json")
		manifestreq.Header.Add("Accept", "application/vnd.docker.distribution.manifest.v1+json")
		manifestreq.Header.Add("Accept", "application/vnd.docker.distribution.manifest.list.v2+json")
		manifestresp, err := client.Do(manifestreq)
		HandleError(err, "Error retrieving manifest file")
		defer manifestresp.Body.Close()
		var manifestfile ManifestReceived
		err = json.NewDecoder(manifestresp.Body).Decode(&manifestfile)
		HandleError(err, "Error in manifest file.")

		handleSingleManifestV2(&manifestfile, &authtoken, client, imageRepository, imagename, tag)

	},
}

func handleSingleManifestV2(manifestReceived *ManifestReceived, authToken *AuthToken, client *http.Client, imageRepository string, imageName string, tag string) {
	imageDir := fmt.Sprintf("/tmp/%s/%s/%s", imageRepository, imageName, tag)
	CreateDirIfNotExist(imageDir)
	manifestSplit := strings.Split(manifestReceived.Config.Digest, ":")
	blobName := manifestSplit[1]
	fileName := blobName + ".json"
	blobUrl := fmt.Sprintf("https://%s/v2/%s/blobs/%s", imageRepository, imageName, manifestReceived.Config.Digest)
	mediaType := manifestReceived.Config.MediaType
	fmt.Printf("Fetching Image Configuration  file..\n")
	fetchBlob(blobUrl, client, fileName, authToken, mediaType, imageDir)
	fmt.Printf("Fetching %s/%s:%s (%d layers): \n ", imageRepository, imageName, tag, len(manifestReceived.Layers))
	repositoryconfigname := fmt.Sprintf("%s/%s", imageRepository, imageName)

	repositoriesjson := fmt.Sprintf("{ %q: { %q:%q }", repositoryconfigname, tag, "")
	err := ioutil.WriteFile(imageDir+"/repositories", []byte(repositoriesjson), 0655)
	HandleError(err, "Cannot write repositories file.")

	/*
	* Downloading layers of the container images.
	 */
	var previousLayerID string = ""
	var layersPlaceholder []string
	for LayerItem := range manifestReceived.Layers {
		mediaType := manifestReceived.Layers[LayerItem].MediaType
		blobUrl := fmt.Sprintf("https://%s/v2/%s/blobs/%s", imageRepository, imageName, manifestReceived.Layers[LayerItem].Digest)
		layeridValues := fmt.Sprintf("%s$\n%s", previousLayerID, manifestReceived.Layers[LayerItem].Digest)

		layerID := fmt.Sprintf("%x", sha256.Sum256([]byte(layeridValues)))
		previousLayerID = layerID
		imageDirLayer := imageDir + "/" + layerID
		if !(exists(imageDirLayer)) {
			CreateDirIfNotExist(imageDirLayer)
			fetchBlob(blobUrl, client, "layer.tar", authToken, mediaType, imageDirLayer)
			versionData := []byte("1.0")
			_ = ioutil.WriteFile(imageDirLayer+"/VERSION", versionData, 0644)
			imageLayerJsonFileData := []byte("{\n  \"id\": \"1e8e26b3eb7a503e10a473effe42c50a09705854f6d5da3d522f9a5acf107c49\",\n  \"created\": \"0001-01-01T00:00:00Z\",\n  \"container_config\": {\n    \"Hostname\": \"\",\n    \"Domainname\": \"\",\n    \"User\": \"\",\n    \"AttachStdin\": false,\n    \"AttachStdout\": false,\n    \"AttachStderr\": false,\n    \"Tty\": false,\n    \"OpenStdin\": false,\n    \"StdinOnce\": false,\n    \"Env\": null,\n    \"Cmd\": null,\n    \"Image\": \"\",\n    \"Volumes\": null,\n    \"WorkingDir\": \"\",\n    \"Entrypoint\": null,\n    \"OnBuild\": null,\n    \"Labels\": null\n  }\n}")
			_ = ioutil.WriteFile(imageDirLayer+"/json", imageLayerJsonFileData, 0644)
		} else {
			fmt.Println("\r Layer already spooled .. skipping..")
		}
		layersPlaceholder = append(layersPlaceholder, layerID+"/layer.tar")

	}

	/*
	* Marshal data to slice and write file manifest.json in root directory of the Image download.
	 */
	manifestforwritedocker := ManifestWriteForDocker{
		Config:   fileName,
		RepoTags: nil,
		Layers:   layersPlaceholder,
	}

	manifestconfigurationrepo := repositoryconfigname + ":" + tag
	repoTags := append(manifestforwritedocker.RepoTags, manifestconfigurationrepo)
	manifestforwritedocker.RepoTags = repoTags
	manifestJsonFileImage := manifestJsonFileImage{
		manifestJsonFileImage: nil,
	}
	manifestjsonfileimage := append(manifestJsonFileImage.manifestJsonFileImage, manifestforwritedocker)
	marshalleddata, _ := json.Marshal(manifestjsonfileimage)
	err = ioutil.WriteFile(imageDir+"/manifest.json", marshalleddata, 0655)
	HandleError(err, "Cannot write manifest file.")

	fmt.Println("Image Download completed.")
	fmt.Printf("Please run command \"tar -cC %s .| docker load\" to load image to the docker daemon.", imageDir)

}

func fetchBlob(blobUrl string, client *http.Client, filename string, token *AuthToken, mediaType string, imageDir string) {

	request, _ := http.NewRequest("GET", blobUrl, nil)
	request.Header.Add("Authorization", "Bearer "+token.Token)
	request.Header.Add("Accept", mediaType)
	response, err := client.Do(request)
	HandleBlobError(err, "error retrieving image layers", imageDir)
	defer response.Body.Close()
	out, err := os.Create(imageDir + "/" + filename + ".tmp")
	HandleBlobError(err, "Error creating file", imageDir)
	counter := &WriteCounter{}
	_, err = io.Copy(out, io.TeeReader(response.Body, counter))
	HandleBlobError(err, "Error copying data of Image layer", imageDir)
	fmt.Println("                                                       ")
	err = os.Rename(imageDir+"/"+filename+".tmp", imageDir+"/"+filename)
	HandleBlobError(err, "Cannot Stat file.", imageDir)

}

func CreateDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
	}
}

func init() {
	rootCmd.AddCommand(pullCmd)
	pullCmd.Flags().StringP("image", "i", "", "Full docker image name without tag")
	pullCmd.Flags().StringP("tag", "t", "", "docker image tag")
	pullCmd.Flags().StringP("username", "u", "", "Username for docker pull")
	pullCmd.Flags().StringP("password", "p", "", "Password")
	_ = pullCmd.MarkFlagRequired("image")
}
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func HandleError(err error, Message string) {
	if err != nil {
		fmt.Println(Message)
	}
}
func HandleBlobError(err error, Message string, imageDir string) {
	if err != nil {
		_ = os.RemoveAll(imageDir)
		fmt.Println(Message)
	}
}
func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

func (wc WriteCounter) PrintProgress() {
	fmt.Printf("\r%s", strings.Repeat(" ", 35))
	fmt.Printf("\rDownloading... %s complete", humanize.Bytes(wc.Total))
}
func exists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}
func CreateTarFile(source, destination string) {
	dir, err := os.Open(source)
	HandleError(err, "Error opening directory")
	defer dir.Close()

	// get list of files
	files, err := dir.Readdir(0)
	HandleError(err, "Error Reading files list for creating archive")

	// create tar file
	tarfile, err := os.Create(destination)
	HandleError(err, "Cannot create archive file")
	defer tarfile.Close()

	var fileWriter io.WriteCloser = tarfile

	tarfileWriter := tar.NewWriter(fileWriter)
	defer tarfileWriter.Close()

	for _, fileInfo := range files {

		if fileInfo.IsDir() {
			continue
		}

		file, err := os.Open(dir.Name() + string(filepath.Separator) + fileInfo.Name())
		HandleError(err, "Error Reading files")
		defer file.Close()

		// prepare the tar header
		header := new(tar.Header)
		header.Name = file.Name()
		header.Size = fileInfo.Size()
		header.Mode = int64(fileInfo.Mode())
		header.ModTime = fileInfo.ModTime()

		err = tarfileWriter.WriteHeader(header)
		HandleError(err, "Error writing tar file header")

		_, err = io.Copy(tarfileWriter, file)
		HandleError(err, "Error writing tar file")
	}

}
