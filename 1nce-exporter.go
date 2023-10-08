package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	simCardIMEIlocked = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "once_sim_card_imei_locked",
		Help: "IMEI lock state of a given SIM card",
	}, []string{"iccid", "imei"})
	simCardDataVolumeRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "once_sim_card_data_volume_remaining",
		Help: "Remaining Data usage of a SIM card in Megabyte",
	}, []string{"iccid"})
	simCardDataVolumeTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "once_sim_card_data_volume_total",
		Help: "Total Data volume ever booked for a SIM card",
	}, []string{"iccid"})
)

type exporterConfiguration struct {
	credentials struct {
		username string
		password string
	}
}

type onceExporter struct {
	configuration exporterConfiguration
	auth          struct {
		token   string
		expires time.Time
	}
}

var exporterState = onceExporter{}

func load_configuration(filepath string) {
	exporterState.configuration.credentials.username = "81029943_dbauerapi"
	exporterState.configuration.credentials.password = "fnsh1nce"
}

func onceAPIFetch(method string, url string, headers map[string]string, payload io.Reader) []byte {
	req, _ := http.NewRequest(method, url, payload)

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()
	fmt.Println(res.Status)
	body, _ := io.ReadAll(res.Body)

	return body
}

func fetchSimCards() {
	type OnceApiManagementSims []struct {
		Iccid          string `json:"iccid"`
		Imsi           string `json:"imsi"`
		Msisdn         string `json:"msisdn"`
		Imei           string `json:"imei,omitempty"`
		ImeiLock       bool   `json:"imei_lock"`
		Status         string `json:"status"`
		ActivationDate string `json:"activation_date"`
		IPAddress      string `json:"ip_address"`
		CurrentQuota   int    `json:"current_quota"`
		QuotaStatus    struct {
			ID          int    `json:"id"`
			Description string `json:"description"`
		} `json:"quota_status"`
		CurrentQuotaSMS int `json:"current_quota_SMS"`
		QuotaStatusSMS  struct {
			ID          int    `json:"id"`
			Description string `json:"description"`
		} `json:"quota_status_SMS"`
		Label string `json:"label,omitempty"`
	}

	headers := map[string]string{
		"accept":        "application/json",
		"authorization": fmt.Sprintf("Bearer %s", exporterState.auth.token)}
	body := onceAPIFetch("GET", "https://api.1nce.com/management-api/v1/sims", headers, nil)

	var apiResponse OnceApiManagementSims
	err := json.Unmarshal(body, &apiResponse)
	if err != nil {
		fmt.Println(err)
	}

	for _, simcard := range apiResponse {
		updateSimCardStatus(simcard.Iccid)
		updateSimCardDataQuota(simcard.Iccid)
		if simcard.ImeiLock {
			simCardIMEIlocked.WithLabelValues(simcard.Iccid, simcard.Imei).Set(1)
		} else {
			simCardIMEIlocked.WithLabelValues(simcard.Iccid, simcard.Imei).Set(0)
		}
	}
}

func updateSimCardStatus(iccid string) {
	type OnceApiManagementSimCardStatus struct {
		Status   string `json:"status"`
		Location struct {
			Iccid           string `json:"iccid"`
			Imsi            string `json:"imsi"`
			LastUpdated     string `json:"last_updated"`
			LastUpdatedGprs string `json:"last_updated_gprs"`
			SgsnNumber      string `json:"sgsn_number"`
			VlrNumber       string `json:"vlr_number"`
			VlrNumberNp     string `json:"vlr_number_np"`
			MscNumberNp     string `json:"msc_number_np"`
			SgsnNumberNp    string `json:"sgsn_number_np"`
			OperatorID      string `json:"operator_id"`
			Msc             string `json:"msc"`
			Operator        struct {
				ID      int    `json:"id"`
				Name    string `json:"name"`
				Country struct {
					ID      int    `json:"id"`
					Name    string `json:"name"`
					IsoCode string `json:"iso_code"`
				} `json:"country"`
			} `json:"operator"`
			Country struct {
				CountryID   string `json:"country_id"`
				Name        string `json:"name"`
				CountryCode string `json:"country_code"`
				Mcc         string `json:"mcc"`
				IsoCode     string `json:"iso_code"`
				Latitude    string `json:"latitude"`
				Longitude   string `json:"longitude"`
			} `json:"country"`
			SgsnIPAddress string `json:"sgsn_ip_address"`
		} `json:"location"`
		PdpContext struct {
			PdpContextID              string `json:"pdp_context_id"`
			EndpointID                string `json:"endpoint_id"`
			TariffProfileID           string `json:"tariff_profile_id"`
			TariffID                  string `json:"tariff_id"`
			RatezoneID                string `json:"ratezone_id"`
			OrganisationID            string `json:"organisation_id"`
			ImsiID                    string `json:"imsi_id"`
			Imsi                      string `json:"imsi"`
			SimID                     string `json:"sim_id"`
			TeidDataPlane             string `json:"teid_data_plane"`
			TeidControlPlane          string `json:"teid_control_plane"`
			GtpVersion                string `json:"gtp_version"`
			Nsapi                     string `json:"nsapi"`
			SgsnControlPlaneIPAddress string `json:"sgsn_control_plane_ip_address"`
			SgsnDataPlaneIPAddress    string `json:"sgsn_data_plane_ip_address"`
			GgsnControlPlaneIPAddress string `json:"ggsn_control_plane_ip_address"`
			GgsnDataPlaneIPAddress    string `json:"ggsn_data_plane_ip_address"`
			Created                   string `json:"created"`
			Mcc                       string `json:"mcc"`
			Mnc                       string `json:"mnc"`
			OperatorID                string `json:"operator_id"`
			Lac                       string `json:"lac"`
			Ci                        string `json:"ci"`
			Sac                       string `json:"sac"`
			Rac                       string `json:"rac"`
			UeIPAddress               string `json:"ue_ip_address"`
			Imeisv                    string `json:"imeisv"`
			RatType                   struct {
				RatTypeID   string `json:"rat_type_id"`
				Description string `json:"description"`
			} `json:"rat_type"`
			Duration string `json:"duration"`
		} `json:"pdp_context"`
		Services []string `json:"services"`
	}

	headers := map[string]string{
		"accept":        "application/json",
		"authorization": fmt.Sprintf("Bearer %s", exporterState.auth.token)}
	body := onceAPIFetch("GET", fmt.Sprintf("https://api.1nce.com/management-api/v1/sims/%s/status", iccid), headers, nil)

	var apiResponse OnceApiManagementSimCardStatus
	err := json.Unmarshal(body, &apiResponse)
	if err != nil {
		fmt.Println(err)
	}

	// ToDo: parse metrics
}

func updateSimCardDataQuota(iccid string) {
	type SimCardDataQuote struct {
		Volume               float64 `json:"volume"`
		TotalVolume          int     `json:"total_volume"`
		ExpiryDate           string  `json:"expiry_date"`
		PeakThroughput       int     `json:"peak_throughput"`
		LastVolumeAdded      int     `json:"last_volume_added"`
		LastStatusChangeDate string  `json:"last_status_change_date"`
		ThresholdPercentage  int     `json:"threshold_percentage"`
	}

	headers := map[string]string{
		"accept":        "application/json",
		"authorization": fmt.Sprintf("Bearer %s", exporterState.auth.token)}
	body := onceAPIFetch("GET", fmt.Sprintf("https://api.1nce.com/management-api/v1/sims/%s/quota/data", iccid), headers, nil)

	var apiResponse SimCardDataQuote
	err := json.Unmarshal(body, &apiResponse)
	if err != nil {
		fmt.Println(err)
	}

	simCardDataVolumeTotal.WithLabelValues(iccid).Set(float64(apiResponse.TotalVolume))
	simCardDataVolumeRemaining.WithLabelValues(iccid).Set(float64(apiResponse.Volume))
}

func requestBearer() {
	authorization := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(
		"%s:%s",
		exporterState.configuration.credentials.username,
		exporterState.configuration.credentials.password)))
	headers := map[string]string{
		"accept":        "application/json",
		"content-type":  "application/json",
		"authorization": fmt.Sprintf("Basic %s", authorization)}
	payload := strings.NewReader("{\"grant_type\":\"client_credentials\"}")
	body := onceAPIFetch("POST", "https://api.1nce.com/management-api/oauth/token", headers, payload)

	type onceApiOauthToken struct {
		StatusCode  int    `json:"status_code"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		UserId      string `json:"userId"`
		Scope       string `json:"scope"`
	}

	var apiResponse onceApiOauthToken

	err := json.Unmarshal(body, &apiResponse)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(apiResponse.AccessToken)
	exporterState.auth.token = apiResponse.AccessToken
	exporterState.auth.expires = time.Now().Add(time.Second * time.Duration(apiResponse.ExpiresIn-10))
}

func checkAndRenewBearer() {
	if time.Now().After(exporterState.auth.expires) {
		requestBearer()
	}
}

func recordMetrics() {
	go func() {
		for {
			fetchSimCards()
			time.Sleep(120 * time.Second)
		}
	}()
}

func main() {
	load_configuration("")
	checkAndRenewBearer()
	recordMetrics()
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}
