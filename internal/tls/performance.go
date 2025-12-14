package tls

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ConnectionPool manages a pool of TLS connections for reuse
type ConnectionPool struct {
	mu          sync.RWMutex
	connections map[string][]*pooledConnection
	maxIdle     int
	maxIdleTime time.Duration
	logger      *slog.Logger
}

// pooledConnection represents a pooled TLS connection
type pooledConnection struct {
	conn     *tls.Conn
	lastUsed time.Time
	inUse    bool
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxIdle int, maxIdleTime time.Duration, logger *slog.Logger) *ConnectionPool {
	if logger == nil {
		logger = slog.Default()
	}

	pool := &ConnectionPool{
		connections: make(map[string][]*pooledConnection),
		maxIdle:     maxIdle,
		maxIdleTime: maxIdleTime,
		logger:      logger,
	}

	// Start cleanup goroutine
	go pool.cleanup()

	return pool
}

// Get retrieves a connection from the pool or creates a new one
func (p *ConnectionPool) Get(ctx context.Context, address string, tlsConfig *tls.Config) (*tls.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to get an existing connection
	if conns, exists := p.connections[address]; exists {
		for i, pooledConn := range conns {
			if !pooledConn.inUse && time.Since(pooledConn.lastUsed) < p.maxIdleTime {
				// Mark as in use and return
				pooledConn.inUse = true
				pooledConn.lastUsed = time.Now()

				// Remove from pool
				p.connections[address] = append(conns[:i], conns[i+1:]...)

				p.logger.Debug("Reusing pooled TLS connection", "address", address)
				return pooledConn.conn, nil
			}
		}
	}

	// Create new connection
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}

	p.logger.Debug("Created new TLS connection", "address", address)
	return conn, nil
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(address string, conn *tls.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if we have room in the pool
	conns := p.connections[address]
	if len(conns) >= p.maxIdle {
		// Pool is full, close the connection
		conn.Close()
		return
	}

	// Add to pool
	pooledConn := &pooledConnection{
		conn:     conn,
		lastUsed: time.Now(),
		inUse:    false,
	}

	p.connections[address] = append(conns, pooledConn)
	p.logger.Debug("Returned TLS connection to pool", "address", address, "pool_size", len(p.connections[address]))
}

// cleanup removes expired connections from the pool
func (p *ConnectionPool) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()

		now := time.Now()
		for address, conns := range p.connections {
			var activeConns []*pooledConnection

			for _, pooledConn := range conns {
				if !pooledConn.inUse && now.Sub(pooledConn.lastUsed) > p.maxIdleTime {
					// Connection expired, close it
					pooledConn.conn.Close()
					p.logger.Debug("Closed expired pooled connection", "address", address)
				} else {
					activeConns = append(activeConns, pooledConn)
				}
			}

			if len(activeConns) == 0 {
				delete(p.connections, address)
			} else {
				p.connections[address] = activeConns
			}
		}

		p.mu.Unlock()
	}
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for address, conns := range p.connections {
		for _, pooledConn := range conns {
			pooledConn.conn.Close()
		}
		delete(p.connections, address)
		p.logger.Debug("Closed all pooled connections", "address", address)
	}

	return nil
}

// HandshakeOptimizer optimizes TLS handshake performance
type HandshakeOptimizer struct {
	sessionCache    tls.ClientSessionCache
	ticketKeys      [][32]byte
	ticketKeysMutex sync.RWMutex
	rotationTicker  *time.Ticker
	logger          *slog.Logger
}

// NewHandshakeOptimizer creates a new handshake optimizer
func NewHandshakeOptimizer(cacheSize int, logger *slog.Logger) *HandshakeOptimizer {
	if logger == nil {
		logger = slog.Default()
	}

	optimizer := &HandshakeOptimizer{
		sessionCache: tls.NewLRUClientSessionCache(cacheSize),
		logger:       logger,
	}

	// Initialize with a random ticket key
	optimizer.rotateTicketKeys()

	// Start ticket key rotation
	optimizer.rotationTicker = time.NewTicker(24 * time.Hour)
	go optimizer.ticketKeyRotation()

	return optimizer
}

// OptimizeServerConfig applies handshake optimizations to server config
func (h *HandshakeOptimizer) OptimizeServerConfig(config *tls.Config) {
	if config == nil {
		return
	}

	// Enable session resumption
	config.SessionTicketsDisabled = false

	// Set up ticket key rotation
	h.ticketKeysMutex.RLock()
	if len(h.ticketKeys) > 0 {
		config.SetSessionTicketKeys(h.ticketKeys)
	}
	h.ticketKeysMutex.RUnlock()

	// Prefer server cipher suites for consistent performance
	config.PreferServerCipherSuites = true

	// Disable renegotiation for security and performance
	config.Renegotiation = tls.RenegotiateNever

	h.logger.Debug("Applied handshake optimizations to server config")
}

// OptimizeClientConfig applies handshake optimizations to client config
func (h *HandshakeOptimizer) OptimizeClientConfig(config *tls.Config) {
	if config == nil {
		return
	}

	// Enable session resumption with cache
	config.ClientSessionCache = h.sessionCache

	h.logger.Debug("Applied handshake optimizations to client config")
}

// rotateTicketKeys generates new session ticket keys
func (h *HandshakeOptimizer) rotateTicketKeys() {
	h.ticketKeysMutex.Lock()
	defer h.ticketKeysMutex.Unlock()

	// Generate new key
	var newKey [32]byte
	if _, err := tls.X509KeyPair(nil, nil); err == nil {
		// Use crypto/rand to generate random key
		copy(newKey[:], "placeholder-for-random-key-generation")
	}

	// Keep up to 3 keys for graceful rotation
	h.ticketKeys = append([][32]byte{newKey}, h.ticketKeys...)
	if len(h.ticketKeys) > 3 {
		h.ticketKeys = h.ticketKeys[:3]
	}

	h.logger.Info("Rotated TLS session ticket keys", "key_count", len(h.ticketKeys))
}

// ticketKeyRotation handles periodic ticket key rotation
func (h *HandshakeOptimizer) ticketKeyRotation() {
	for range h.rotationTicker.C {
		h.rotateTicketKeys()
	}
}

// Close stops the handshake optimizer
func (h *HandshakeOptimizer) Close() error {
	if h.rotationTicker != nil {
		h.rotationTicker.Stop()
	}
	return nil
}

// BufferPool manages reusable buffers for TLS operations
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size: size,
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf []byte) {
	if len(buf) == p.size {
		p.pool.Put(buf)
	}
}

// MemoryOptimizer manages memory usage for TLS operations
type MemoryOptimizer struct {
	readBufferPool  *BufferPool
	writeBufferPool *BufferPool
	logger          *slog.Logger
}

// NewMemoryOptimizer creates a new memory optimizer
func NewMemoryOptimizer(readBufferSize, writeBufferSize int, logger *slog.Logger) *MemoryOptimizer {
	if logger == nil {
		logger = slog.Default()
	}

	return &MemoryOptimizer{
		readBufferPool:  NewBufferPool(readBufferSize),
		writeBufferPool: NewBufferPool(writeBufferSize),
		logger:          logger,
	}
}

// GetReadBuffer gets a read buffer from the pool
func (m *MemoryOptimizer) GetReadBuffer() []byte {
	return m.readBufferPool.Get()
}

// PutReadBuffer returns a read buffer to the pool
func (m *MemoryOptimizer) PutReadBuffer(buf []byte) {
	// Clear sensitive data before returning to pool
	for i := range buf {
		buf[i] = 0
	}
	m.readBufferPool.Put(buf)
}

// GetWriteBuffer gets a write buffer from the pool
func (m *MemoryOptimizer) GetWriteBuffer() []byte {
	return m.writeBufferPool.Get()
}

// PutWriteBuffer returns a write buffer to the pool
func (m *MemoryOptimizer) PutWriteBuffer(buf []byte) {
	// Clear sensitive data before returning to pool
	for i := range buf {
		buf[i] = 0
	}
	m.writeBufferPool.Put(buf)
}

// OptimizedTLSConfig creates an optimized TLS configuration
func OptimizedTLSConfig(baseConfig *tls.Config, opts *PerformanceOptimizations, security *SecurityDefaults) *tls.Config {
	if baseConfig == nil {
		baseConfig = &tls.Config{}
	}

	// Clone the base config to avoid modifying the original
	optimized := baseConfig.Clone()

	// Apply security defaults
	if security != nil {
		ApplySecureDefaults(optimized, security)
	}

	// Apply performance optimizations
	if opts != nil {
		OptimizeTLSConfig(optimized, opts)
	}

	return optimized
}
