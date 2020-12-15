/*
Copyright © 2020 amit dixit
*/
package cmd

import (
	"encoding/base64"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
)

/*
 *  CLI setup
 */
var initcliCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialse CLI defaults",
	Long:  `Initialize cli defaults (create container-pull.yaml in the root directory).`,
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		viper.Set("username", username)
		viper.Set("password", base64.StdEncoding.EncodeToString([]byte(password)))
		_ = viper.WriteConfig()
		log.Printf("configuration file %s created/updated ", viper.GetViper().ConfigFileUsed())
	},
}

/*
* init function to setup init subcommand.
 */
func init() {
	rootCmd.AddCommand(initcliCmd)
	initcliCmd.Flags().StringP("username", "u", "", "coastguard username")
	initcliCmd.Flags().StringP("password", "p", "", "coastguard password")
	_ = initcliCmd.MarkFlagRequired("username")
	_ = initcliCmd.MarkFlagRequired("password")

}
