//  Copyright (c) 2022 Cisco Systems, Inc. and others.  All rights reserved.
package cmd

import (
	"fmt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/openbmp/obmp-whois/config"
	whois "github.com/openbmp/obmp-whois/pkg/whois"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var cfgFile string
var cfgDebug bool

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "obmp-whoisd",
	Short: "OpenBMP Whois Daemon",
	Long:  `OpenBMP Server whois daemon`,

	Run: func(cmd *cobra.Command, args []string) {
		if cfgDebug {
			log.SetLevel(log.DebugLevel)
			log.SetOutput(os.Stdout)
		} else {
			log.SetLevel(log.InfoLevel)

			logfile, err := os.OpenFile(config.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
			if err != nil {
				fmt.Printf("Failed to create log file '%s", config.LogFile)
				os.Exit(1)
			}

			log.SetOutput(logfile)
		}

		whois.Start()

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {
	viper.AutomaticEnv()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is $HOME/whoisd.yaml)")

	rootCmd.PersistentFlags().StringVar(&config.LogFile, "logfile", "/var/log/whoisd.log",
		"log filename")

	rootCmd.PersistentFlags().IntVarP(&config.ListeningPort, "port", "p", 43,
		"Listening port")

	rootCmd.PersistentFlags().StringVar(&config.PgHost, "pghost", viper.GetString("POSTGRES_HOST"),
		"Postgres Hostname, default is env POSTGRES_PORT")

	rootCmd.PersistentFlags().IntVar(&config.PgPort, "pgport", viper.GetInt("POSTGRES_PORT"),
		"Postgre port, default is PGPORT")

	rootCmd.PersistentFlags().StringVar(&config.PgDbname, "pgdb", viper.GetString("POSTGRES_DB"),
		"Postgres database name, default is POSTGRES_DB")

	rootCmd.PersistentFlags().StringVar(&config.PgUser, "pguser", viper.GetString("POSTGRES_USER"),
		"Postgres username, default is POSTGRES_USER")

	rootCmd.PersistentFlags().StringVar(&config.PgPassword, "pgpassword", viper.GetString("POSTGRES_PASSWORD"),
		"Postgres password, default is POSTGRES_PASSWORD.")

	rootCmd.PersistentFlags().IntVarP(&config.MaxThreads, "threads", "t", 10,
		"Max number of threads to handle active connections")

	rootCmd.PersistentFlags().BoolVar(&cfgDebug, "debug", false,
		"Debug logging")

	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		CallerPrettyfier:       logCbPrettyfier,
		ForceColors:            false,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		TimestampFormat:        time.RFC3339Nano,
	})

	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}

		// Search config in home directory (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".whoisd")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func logCbPrettyfier(frame *runtime.Frame) (function string, file string) {
	var sb strings.Builder
	sb.WriteString(path.Base(frame.Function))
	sb.WriteByte('[')
	sb.WriteString(strconv.Itoa(frame.Line))
	sb.WriteByte(']')

	return sb.String(), path.Base(frame.File)
}
