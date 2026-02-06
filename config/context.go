package config

import (
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/util"
	"github.com/gin-gonic/gin"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RussellLuo/timingwheel"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/common"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/cache"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/db"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/log"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/pool"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/redis"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/wkevent"
	"github.com/TangSengDaoDao/TangSengDaoDaoServerLib/pkg/wkhttp"
	"github.com/bwmarrin/snowflake"
	"github.com/gocraft/dbr/v2"
	"github.com/olivere/elastic"
	"github.com/opentracing/opentracing-go"
)

// Context 配置上下文
type Context struct {
	cfg          *Config
	mySQLSession *dbr.Session
	redisCache   *common.RedisCache
	memoryCache  cache.Cache
	log.Log
	EventPool      pool.Collector
	PushPool       pool.Collector // 离线push
	RobotEventPool pool.Collector // 机器人事件pool
	Event          wkevent.Event
	elasticClient  *elastic.Client
	UserIDGen      *snowflake.Node          // 消息ID生成器
	tracer         *Tracer                  // 调用链追踪
	aysncTask      *AsyncTask               // 异步任务
	timingWheel    *timingwheel.TimingWheel // Time wheel delay task

	httpRouter *wkhttp.WKHttp

	valueMap  sync.Map
	SetupTask bool // 是否安装task
}

// NewContext NewContext
func NewContext(cfg *Config) *Context {
	userIDGen, err := snowflake.NewNode(int64(cfg.Cluster.NodeID))
	if err != nil {
		panic(err)
	}
	c := &Context{
		cfg:            cfg,
		UserIDGen:      userIDGen,
		Log:            log.NewTLog("Context"),
		EventPool:      pool.StartDispatcher(cfg.EventPoolSize),
		PushPool:       pool.StartDispatcher(cfg.Push.PushPoolSize),
		RobotEventPool: pool.StartDispatcher(cfg.Robot.EventPoolSize),
		aysncTask:      NewAsyncTask(cfg),
		timingWheel:    timingwheel.NewTimingWheel(cfg.TimingWheelTick.Duration, cfg.TimingWheelSize),
		valueMap:       sync.Map{},
	}
	c.tracer, err = NewTracer(cfg)
	if err != nil {
		panic(err)
	}
	opentracing.SetGlobalTracer(c.tracer)
	c.timingWheel.Start()
	return c
}

// GetConfig 获取配置信息
func (c *Context) GetConfig() *Config {
	return c.cfg
}

// NewMySQL 创建mysql数据库实例
func (c *Context) NewMySQL() *dbr.Session {

	if c.mySQLSession == nil {
		c.mySQLSession = db.NewMySQL(c.cfg.DB.MySQLAddr, c.cfg.DB.MySQLMaxOpenConns, c.cfg.DB.MySQLMaxIdleConns, c.cfg.DB.MySQLConnMaxLifetime)
	}

	return c.mySQLSession
}

// AsyncTask 异步任务
func (c *Context) AsyncTask() *AsyncTask {
	return c.aysncTask
}

// Tracer Tracer
func (c *Context) Tracer() *Tracer {
	return c.tracer
}

// DB DB
func (c *Context) DB() *dbr.Session {
	return c.NewMySQL()
}

// NewRedisCache 创建一个redis缓存
func (c *Context) NewRedisCache() *common.RedisCache {
	if c.redisCache == nil {
		c.redisCache = common.NewRedisCache(c.cfg.DB.RedisAddr, c.cfg.DB.RedisPass)
	}
	return c.redisCache
}

// NewMemoryCache 创建一个内存缓存
func (c *Context) NewMemoryCache() cache.Cache {
	if c.memoryCache == nil {
		c.memoryCache = common.NewMemoryCache()
	}
	return c.memoryCache
}

// Cache 缓存
func (c *Context) Cache() cache.Cache {
	return c.NewRedisCache()
}

// 认证中间件
func (c *Context) AuthMiddleware(r *wkhttp.WKHttp) wkhttp.HandlerFunc {

	return r.AuthMiddleware(c.Cache(), c.cfg.Cache.TokenCachePrefix)
}

// 认证中间件 - Token + IP白名单 + RBAC权限
func (c *Context) AuthMiddlewareForIpRBAC(r *wkhttp.WKHttp) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {

		// Token 校验
		c.checkAuth(ctx, c.Cache(), c.cfg.Cache.TokenCachePrefix)
		if ctx.IsAborted() {
			return
		}

		// IP 白名单
		c.checkAdminIPWhitelist(ctx)
		if ctx.IsAborted() {
			return
		}

		// RBAC 权限
		c.checkAdminPermission(ctx)
		if ctx.IsAborted() {
			return
		}

		ctx.Next()
	}
}

// 认证中间件 - 签名
func (c *Context) AuthMiddlewareForSign(r *wkhttp.WKHttp, secret string) wkhttp.HandlerFunc {
	return func(ctx *wkhttp.Context) {
		// 1. 获取 query 参数
		query := ctx.Request.URL.Query()

		// 2. 取出 sign 并删除（不要参与签名）
		sign := query.Get("sign")
		if sign == "" {
			ctx.Abort()
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"msg": "miss sign",
			})
			return
		}
		query.Del("sign")

		// 3. 按 key 排序拼接字符串
		keys := make([]string, 0, len(query))
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var sb strings.Builder
		for i, k := range keys {
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(query.Get(k)) // 这里只取第一个值，如果多值可自定义
			if i < len(keys)-1 {
				sb.WriteString("&")
			}
		}

		// 5. 计算签名
		expected := util.HmacSha256(sb.String(), secret)

		// 6. 对比
		if !strings.EqualFold(expected, sign) {
			ctx.Abort()
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"msg": "invalid sign",
			})
			return
		}

		// 校验通过
		ctx.Next()
	}
}

func (c *Context) GetLoginUID(token string, tokenPrefix string, cache cache.Cache) string {
	uid, err := cache.Get(tokenPrefix + token)
	if err != nil {
		return ""
	}
	return uid
}

func (c *Context) checkAuth(ctx *wkhttp.Context, cache cache.Cache, tokenPrefix string) {
	token := ctx.GetHeader("token")
	if token == "" {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "token不能为空，请先登录！",
		})
		return
	}

	uidAndName := c.GetLoginUID(token, tokenPrefix, cache)
	if strings.TrimSpace(uidAndName) == "" {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "请先登录！",
		})
		return
	}

	uidAndNames := strings.Split(uidAndName, "@")
	if len(uidAndNames) < 2 {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "token有误！",
		})
		return
	}

	ctx.Set("uid", uidAndNames[0])
	ctx.Set("name", uidAndNames[1])
	if len(uidAndNames) > 2 {
		ctx.Set("role", uidAndNames[2])
	}
}

func (c *Context) checkAdminIPWhitelist(ctx *wkhttp.Context) {
	ip := ctx.ClientIP()

	allowed, err := c.isIPInAdminWhitelist(ip)
	if err != nil {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "当前IP不在后台访问白名单中！",
		})
		return
	}

	if !allowed {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "当前IP不在后台访问白名单中！",
		})
		return
	}
}

func (c *Context) checkAdminPermission(ctx *wkhttp.Context) {
	adminUID := ctx.GetLoginUID()

	path := ctx.Request.URL.Path
	method := ctx.Request.Method

	ok, err := c.adminPermission(adminUID, method, path)
	if err != nil {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "无权限访问该接口！",
		})
		return
	}

	if !ok {
		ctx.Abort()
		ctx.JSON(http.StatusUnauthorized, gin.H{
			"msg": "无权限访问该接口！",
		})
		return
	}
}

// isIPInAdminWhitelist 判断IP是否在后台白名单中
func (m *Context) isIPInAdminWhitelist(ip string) (bool, error) {
	if ip == "127.0.0.1" || ip == "0.0.0.0" {
		return true, nil
	}

	var cnt int64

	_, err := m.mySQLSession.
		Select("COUNT(1)").
		From("admin_ip_whitelist").
		Where("status = 1 AND ip = INET6_ATON(?)", ip).
		Load(&cnt)
	if err != nil {
		return false, err
	}

	return cnt > 0, nil
}

// checkAdminPermission 判断管理员是否有接口访问权限（TODO: 待实现）
func (m *Context) adminPermission(
	adminUID string,
	method string,
	path string,
) (bool, error) {
	// TODO: 后续实现 RBAC 菜单 / API 权限校验
	return true, nil
}

// GetRedisConn GetRedisConn
func (c *Context) GetRedisConn() *redis.Conn {
	return c.NewRedisCache().GetRedisConn()
}

// EventBegin 开启事件
func (c *Context) EventBegin(data *wkevent.Data, tx *dbr.Tx) (int64, error) {
	return c.Event.Begin(data, tx)
}

// EventCommit 提交事件
func (c *Context) EventCommit(eventID int64) {
	c.Event.Commit(eventID)
}

// Schedule 延迟任务
func (c *Context) Schedule(interval time.Duration, f func()) *timingwheel.Timer {
	return c.timingWheel.ScheduleFunc(&everyScheduler{
		Interval: interval,
	}, f)
}

func (c *Context) GetHttpRoute() *wkhttp.WKHttp {
	return c.httpRouter
}

func (c *Context) SetHttpRoute(r *wkhttp.WKHttp) {
	c.httpRouter = r
}

func (c *Context) SetValue(value interface{}, key string) {
	c.valueMap.Store(key, value)
}

func (c *Context) Value(key string) any {
	v, _ := c.valueMap.Load(key)
	return v
}

// OnlineStatus 在线状态
type OnlineStatus struct {
	UID              string // 用户uid
	DeviceFlag       uint8  // 设备标记
	Online           bool   // 是否在线
	SocketID         int64  // 当前设备在wukongim中的在线/离线的socketID
	OnlineCount      int    //在线数量 当前DeviceFlag下的在线设备数量
	TotalOnlineCount int    // 当前用户所有在线设备数量
}

// OnlineStatusListener 在线状态监听
type OnlineStatusListener func(onlineStatusList []OnlineStatus)

var onlinStatusListeners = make([]OnlineStatusListener, 0)

// AddOnlineStatusListener 添加在线状态监听
func (c *Context) AddOnlineStatusListener(listener OnlineStatusListener) {
	onlinStatusListeners = append(onlinStatusListeners, listener)
}

// GetAllOnlineStatusListeners 获取所有在线监听者
func (c *Context) GetAllOnlineStatusListeners() []OnlineStatusListener {
	return onlinStatusListeners
}

// EventCommit 事件提交
type EventCommit func(err error)

// EventListener EventListener
type EventListener func(data []byte, commit EventCommit)

var eventListeners = map[string][]EventListener{}

// AddEventListener  添加事件监听
func (c *Context) AddEventListener(event string, listener EventListener) {
	listeners := eventListeners[event]
	if listeners == nil {
		listeners = make([]EventListener, 0)
	}
	listeners = append(listeners, listener)
	eventListeners[event] = listeners
}

// GetEventListeners 获取某个事件
func (c *Context) GetEventListeners(event string) []EventListener {
	return eventListeners[event]
}

// MessagesListener 消息监听者
type MessagesListener func(messages []*MessageResp)

var messagesListeners = make([]MessagesListener, 0)

// AddMessagesListener 添加消息监听者
func (c *Context) AddMessagesListener(listener MessagesListener) {
	messagesListeners = append(messagesListeners, listener)
}

// NotifyMessagesListeners 通知消息监听者
func (c *Context) NotifyMessagesListeners(messages []*MessageResp) {
	for _, messagesListener := range messagesListeners {
		messagesListener(messages)
	}
}

type everyScheduler struct {
	Interval time.Duration
}

func (s *everyScheduler) Next(prev time.Time) time.Time {
	return prev.Add(s.Interval)
}
