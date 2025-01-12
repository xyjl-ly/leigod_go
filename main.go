package main

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ApiClient 类
type ApiClient struct {
	BaseURL   string
	SignKey   string
	Token     string
	UserNamne string
	TimeLen   string
	Client    *http.Client
}

// NewApiClient 初始化 ApiClient
func NewApiClient(baseURL, signKey string) *ApiClient {
	return &ApiClient{
		BaseURL: baseURL,
		SignKey: signKey,
		Client:  &http.Client{},
	}
}

// generateMD5 生成 MD5 字符串
func (api *ApiClient) generateMD5(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

// generateSign 生成签名
func (api *ApiClient) generateSign(data map[string]string) map[string]string {
	// 获取当前时间戳
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	data["ts"] = ts

	// 将键按字典序排序
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// 构建查询字符串
	queryString := ""
	for _, key := range keys {
		queryString += fmt.Sprintf("%s=%s&", key, url.QueryEscape(data[key]))
	}
	queryString += fmt.Sprintf("key=%s", api.SignKey)

	// 生成 MD5 签名
	signValue := api.generateMD5(queryString)

	// 返回数据，包含签名和时间戳
	data["sign"] = signValue
	data["ts"] = ts
	return data
}

// sendRequest 发送 HTTP 请求
func (api *ApiClient) sendRequest(endpoint string, data map[string]string) ([]byte, error) {
	data = api.generateSign(data)
	// 将数据转换为 JSON 格式
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("JSON 转换失败: %v", err)
	}

	// 创建 POST 请求
	req, err := http.NewRequest("POST", api.BaseURL+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("请求创建失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")
	req.Header.Set("Sec-Ch-Ua", `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	req.Header.Set("Referer", "https://vip.leigod.com/")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")

	// 执行请求
	resp, err := api.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("执行请求时出错: %v", err)
	}
	defer resp.Body.Close()

	// 判断是否是 gzip 压缩
	var body []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("解压 gzip 响应时出错: %v", err)
		}
		defer gzipReader.Close()

		body, err = io.ReadAll(gzipReader)
		if err != nil {
			return nil, fmt.Errorf("读取解压后数据时出错: %v", err)
		}
	} else {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("读取响应时出错: %v", err)
		}
	}

	return body, nil
}

// login 登录并获取 token
func (api *ApiClient) login(username, password string) error {
	// 准备登录请求数据
	data := map[string]string{
		"username":     username,
		"password":     api.generateMD5(password), // 对密码进行 MD5 加密
		"src_channel":  "guanwang",
		"region_code":  "1",
		"user_type":    "0",
		"code":         "",
		"country_code": "86",
		"lang":         "zh_CN",
		"os_type":      "4",
	}

	// 发送登录请求
	body, err := api.sendRequest("/api/auth/login/v1", data)
	if err != nil {
		return fmt.Errorf("登录失败: %v", err)
	}

	// 解析登录响应数据
	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return fmt.Errorf("解析登录响应数据失败: %v", err)
	}

	// 获取 token
	if responseData["code"].(float64) == 0 {
		loginInfo := responseData["data"].(map[string]interface{})["login_info"].(map[string]interface{})
		api.Token = loginInfo["account_token"].(string)
	} else {
		return fmt.Errorf("登录失败: %v", responseData["msg"])
	}

	return nil
}

// getUserInfo 获取用户信息
func (api *ApiClient) getUserInfo() (map[string]interface{}, error) {
	// 准备请求数据
	data := map[string]string{
		"account_token": api.Token,
		"lang":          "zh_CN",
	}

	// 发送请求获取用户信息
	body, err := api.sendRequest("/api/user/info", data)
	if err != nil {
		return nil, fmt.Errorf("获取用户信息失败: %v", err)
	}

	// 解析响应数据
	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return nil, fmt.Errorf("解析响应数据失败: %v", err)
	}

	// 判断是否成功
	if responseData["code"].(float64) == 0 {
		// 获取用户信息
		userInfo := responseData["data"].(map[string]interface{})
		api.UserNamne = userInfo["mobile"].(string)
		api.TimeLen = userInfo["expiry_time"].(string)
		return responseData["data"].(map[string]interface{}), nil

	} else {
		return nil, fmt.Errorf("获取用户信息失败: %v", responseData["msg"])
	}
}

// isTimePaused 判断用户是否暂停
func (api *ApiClient) isTimePaused() (bool, error) {
	userInfo, err := api.getUserInfo()
	if err != nil {
		return false, err
	}

	// 获取暂停状态
	status, ok := userInfo["pause_status_id"].(float64)
	if !ok {
		return false, fmt.Errorf("无法解析暂停状态")
	}

	// 判断状态是否为暂停状态
	return status == 1, nil
}

// pauseTime 尝试暂停时间
func (api *ApiClient) pauseTime() error {
	// 准备暂停请求数据
	data := map[string]string{
		"account_token": api.Token,
		"lang":          "zh_CN",
	}

	// 发送暂停时间请求
	body, err := api.sendRequest("/api/user/pause", data)
	if err != nil {
		return fmt.Errorf("暂停时间失败: %v", err)
	}

	// 解析响应数据
	var responseData map[string]interface{}
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return fmt.Errorf("解析暂停响应数据失败: %v", err)
	}

	// 判断返回的 msg 是否为暂停成功
	if responseData["code"].(float64) != 0 {
		return fmt.Errorf("暂停失败: %v", responseData["msg"])
	}

	return nil
}

// checkAndPauseTime 检查时长是否暂停并尝试暂停
func (api *ApiClient) checkAndPauseTime() {
	// 检查时长是否暂停
	isPaused, err := api.isTimePaused()
	if err != nil {
		fmt.Println("检查时长状态时出错:", err)
		return
	}

	if !isPaused {
		fmt.Println("时长未暂停，尝试暂停时间...")
		// 尝试暂停时间
		err = api.pauseTime()
		if err != nil {
			fmt.Println("暂停时间失败:", err)
		} else {
			// 再次检查暂停状态
			isPaused, err = api.isTimePaused()
			if err != nil {
				fmt.Println("检查暂停状态时出错:", err)
				return
			}

			if isPaused {
				fmt.Println("时长已成功暂停")
			} else {
				fmt.Println("时长暂停失败")
			}
		}
	} else {
		fmt.Println("时长已暂停")
	}
	fmt.Println("用户名:", api.UserNamne, "当前剩余时间:", api.TimeLen)

}

// checkProcessExists 检查指定进程是否存在
func checkProcessExists(processName string) bool {
	// 使用 tasklist 获取当前运行的进程列表（适用于 Windows 系统）
	cmd := exec.Command("tasklist")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("无法获取任务列表:", err)
		return false
	}

	// 判断进程是否存在
	return strings.Contains(strings.ToLower(string(output)), strings.ToLower(processName))
}

func main() {
	username := ""
	password := ""
	// 需要监控的进程列表
	processes := []string{"pubg.exe"}

	processStatus := make(map[string]bool)
	checkInterval := 1 * time.Second

	// 初始化 API 客户端
	apiClient := NewApiClient("https://webapi.leigod.com", "5C5A639C20665313622F51E93E3F2783")

	// 登录获取 token
	err := apiClient.login(username, password)
	if err != nil {
		fmt.Println("登录失败:", err)
		return
	}
	apiClient.getUserInfo()

	fmt.Println("用户名:", apiClient.UserNamne, "当前剩余时间:", apiClient.TimeLen)
	fmt.Println("开始监控进程状态...")
	// 持续检测
	for {
		for _, process := range processes {
			exists := checkProcessExists(process)
			previousStatus, known := processStatus[process]

			// 如果当前进程第一次存在或者之前没有标记过为存在
			if exists && (!known || !previousStatus) {
				fmt.Printf("进程 %s 已启动\n", process)
				processStatus[process] = true // 标记进程存在
			} else if !exists && previousStatus {
				// 如果进程之前标记为存在，但现在不存在
				fmt.Printf("进程 %s 已结束\n", process)
				processStatus[process] = false // 标记进程结束
				// 检查并暂停时间
				apiClient.checkAndPauseTime()
			}

			// 如果进程状态没有变化，则不输出任何信息
		}

		// 间隔指定时间后继续检测
		time.Sleep(checkInterval)
	}

}
