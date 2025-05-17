package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Port                    string `mapstructure:"PORT"`
	Env                     string `mapstructure:"ENV"`
	DbHost                  string `mapstructure:"DB_HOST"`
	DbPort                  string `mapstructure:"DB_PORT"`
	DbUser                  string `mapstructure:"DB_USER"`
	DbPass                  string `mapstructure:"DB_PASSWORD"`
	DbName                  string `mapstructure:"DB_NAME"`
	TokenSymmetricKey       string `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	SecretsSymmetricKey     string `mapstructure:"SECRETS_SYMMETRIC_KEY"`
	DBSource                string
	AccessTokenDuration     time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	ExpirationCheckInterval time.Duration `mapstructure:"EXPIRATION_CHECK_INTERVAL"`
	RedisAddr               string        `mapstructure:"REDIS_ADDR"`
	RateLimitTokens         int           `mapstructure:"RATE_LIMIT_TOKENS"`
	RateLimitRefill         float64       `mapstructure:"RATE_LIMIT_REFILL"`
}

func LoadConfig(path string) (config Config, err error) {

	viper.AddConfigPath(path)
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return
	}

	config.DBSource = "postgres://" + config.DbUser + ":" + config.DbPass + "@" +
		config.DbHost + ":" + config.DbPort + "/" + config.DbName + "?sslmode=disable"

	return config, nil

}
