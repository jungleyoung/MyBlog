package com.julex.blogclient.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@Configuration
@EnableWebSecurity
public class SecurityConf extends WebSecurityConfigurerAdapter {
    /**
     * 新增Security
     * 授权账户
     * @param auth
     * @throws Exception
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        /**
//         * 账号、密码、接口权限
//         */
//        auth.inMemoryAuthentication().withUser("admin").password("admin").authorities("add","update","get","del");
//        auth.inMemoryAuthentication().withUser("add").password("add").authorities("add");
//        auth.inMemoryAuthentication().withUser("update").password("update").authorities("update");
//        auth.inMemoryAuthentication().withUser("get").password("get").authorities("get");
//        auth.inMemoryAuthentication().withUser("del").password("del").authorities("del");
//        auth.inMemoryAuthentication().withUser("user").password("user").authorities("del");
//    }
    /**
     * 认证方式
     * @param http
     * @throws Exception
     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        /**
//         * 基础认证
//         */
//        //http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();
//        /**
//         * form表单验证
//         */
////        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();
//        /**
//         * 拦截规则
//         */
////        http.authorizeRequests().antMatchers("/add").hasAnyAuthority("add")
////                .antMatchers("/get").hasAnyAuthority("get")
////                .antMatchers("/update").hasAnyAuthority("update")
////                .antMatchers("/del").hasAnyAuthority("del")
////                //form验证
////                .antMatchers("/**").fullyAuthenticated().and().formLogin();
//        /**
//         * 自定义登录页
//         */
////        http.csrf().disable().formLogin().loginPage("/myLogin").loginProcessingUrl("/myLogin");//自定义登录请求路径
//
//    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("css/**");
    }
    /**
     * 加密方式，恢复以前模式
     * @return
     */
//    @Bean
//    public static NoOpPasswordEncoder PasswordEncoder(){
//        return (NoOpPasswordEncoder)NoOpPasswordEncoder.getInstance();
//    }
}
