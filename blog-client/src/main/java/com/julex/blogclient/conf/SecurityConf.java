package com.julex.blogclient.conf;

import com.julex.blogclient.code.ValidateCodeFilter;
import com.julex.blogclient.handler.MyAuthenticationFailureHandler;
import com.julex.blogclient.handler.MyAuthenticationSucessHandler;
import com.julex.blogclient.service.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import javax.annotation.Resource;
import javax.sql.DataSource;


@Configuration
@EnableWebSecurity
public class SecurityConf extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;

    @Autowired
    private ValidateCodeFilter validateCodeFilter;
    @Autowired
    private UserDetailService userDetailService;
    @Resource
    private DataSource dataSource;


    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        jdbcTokenRepository.setCreateTableOnStartup(false);
        return jdbcTokenRepository;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    /**
     * ??????Security
     * ????????????
     * @param auth
     * @throws Exception
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        /**
//         * ??????????????????????????????
//         */
//        auth.inMemoryAuthentication().withUser("admin").password("admin").authorities("add","update","get","del");
//        auth.inMemoryAuthentication().withUser("add").password("add").authorities("add");
//        auth.inMemoryAuthentication().withUser("update").password("update").authorities("update");
//        auth.inMemoryAuthentication().withUser("get").password("get").authorities("get");
//        auth.inMemoryAuthentication().withUser("del").password("del").authorities("del");
//        auth.inMemoryAuthentication().withUser("user").password("user").authorities("del");
//    }
    /**
     * ????????????
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * ????????????
         */
        //http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();
        /**
         * form????????????
         */
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();
        /**
         * ????????????
         */
//        http.authorizeRequests().antMatchers("/add").hasAnyAuthority("add")
//                .antMatchers("/get").hasAnyAuthority("get")
//                .antMatchers("/update").hasAnyAuthority("update")
//                .antMatchers("/del").hasAnyAuthority("del")
//                //form??????
//                .antMatchers("/**").fullyAuthenticated().and().formLogin();
        /**
         * ??????????????????
         */
//        http.csrf().disable().formLogin().loginPage("/myLogin").loginProcessingUrl("/myLogin");//???????????????????????????
        http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class) // ??????????????????????????????
                .formLogin() // ????????????
                // http.httpBasic() // HTTP Basic
                .loginPage("/myLogin") // ???????????? URL
                .loginProcessingUrl("/login") // ?????????????????? URL
                .successHandler(authenticationSucessHandler) // ??????????????????
                .failureHandler(authenticationFailureHandler) // ??????????????????
                .and()
                .rememberMe()
                .tokenRepository(persistentTokenRepository()) // ?????? token ???????????????
                .tokenValiditySeconds(3600) // remember ????????????????????????
                .userDetailsService(userDetailService) // ????????????????????????
                .and()
                .authorizeRequests() // ????????????
                .antMatchers("/myLogin",
                        "/css/**",
                        "/code/image").permitAll() // ???????????????????????????
                .anyRequest()  // ????????????
                .authenticated() // ???????????????
                .and()
                .csrf().disable();
    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("css/**");
//    }
    /**
     * ?????????????????????????????????
     * @return
     */
//    @Bean
//    public static NoOpPasswordEncoder PasswordEncoder(){
//        return (NoOpPasswordEncoder)NoOpPasswordEncoder.getInstance();
//    }
}
