package com.julex.blogclient.conf;

import com.julex.blogclient.handler.MyAuthenticationFailureHandler;
import com.julex.blogclient.handler.MyAuthenticationSucessHandler;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private MyAuthenticationSucessHandler authenticationSucessHandler;

    @Autowired
    private MyAuthenticationFailureHandler authenticationFailureHandler;
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
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 基础认证
         */
        //http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().httpBasic();
        /**
         * form表单验证
         */
//        http.authorizeRequests().antMatchers("/**").fullyAuthenticated().and().formLogin();
        /**
         * 拦截规则
         */
//        http.authorizeRequests().antMatchers("/add").hasAnyAuthority("add")
//                .antMatchers("/get").hasAnyAuthority("get")
//                .antMatchers("/update").hasAnyAuthority("update")
//                .antMatchers("/del").hasAnyAuthority("del")
//                //form验证
//                .antMatchers("/**").fullyAuthenticated().and().formLogin();
        /**
         * 自定义登录页
         */
//        http.csrf().disable().formLogin().loginPage("/myLogin").loginProcessingUrl("/myLogin");//自定义登录请求路径
        http.formLogin() // 表单登录
                // http.httpBasic() // HTTP Basic
//                .loginPage("/authentication/require") // 登录跳转 URL
                .loginPage("/myLogin") // 登录跳转 URL
                .loginProcessingUrl("/login") // 处理表单登录 URL
                .successHandler(authenticationSucessHandler).failureHandler(authenticationFailureHandler)
                .and()
                .authorizeRequests() // 授权配置
                .antMatchers( "/myLogin","/css/**").permitAll() // 登录跳转 URL 无需认证
                .anyRequest()  // 所有请求
                .authenticated() // 都需要认证
                .and().csrf().disable();
    }

//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("css/**");
//    }
    /**
     * 加密方式，恢复以前模式
     * @return
     */
//    @Bean
//    public static NoOpPasswordEncoder PasswordEncoder(){
//        return (NoOpPasswordEncoder)NoOpPasswordEncoder.getInstance();
//    }
}
