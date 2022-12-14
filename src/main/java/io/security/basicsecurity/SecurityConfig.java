package io.security.basicsecurity;

// 2022 9월 기준 최신 버전 스프링부트 사용했을때 권장되는 스프링 시큐리티 설정 클래스

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

//@Configuration //EnableWebSecurity 안에 @Configuration 포함됨
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
/**
 * to-do list : 인텔리제이 디버깅 , evalution tab 알아보기 java-docs , 빌더 패턴 , 어댑터 패턴 , @커스텀 어노테이션(interface) 생성 , 커스텀 필터 추가해보기, 스레드
 *  익명 클래스
 * 자세한 필터 설명은 강의자료에..
 *
 * Authentication : User, Authorities 를 가지는 인증객체
 * SecurityContext : Authentication 객체 저장소 class
 * SecurityContext 객체는 나중에 세션(HttpSession class)에 저장된다
 *
 * rememberMe 설정을 켜면 remember-me 라는 이름의 쿠키가 생성되고 , 이 쿠키 안에 인증정보가 담겨 있다
 * 개발자도구상에서 jsessionid를 일부러 삭제하고 재요청해도 다시 인증하지 않아도 된다.
 * rememberMe 쿠키가 없는 상황에서는 jsessionid 쿠키를 삭제했을때 인증페이지(로그인)으로 리다이렉트된다다
 * RememberMeAuthenticationFilter가 동작할 2가지 조건 1. Authentication 객체가 null 이면서(세션 만료) 2. 사용자가 요청 헤더에 remeber-me cookie 값을 가지고 있을 때
 * 다시 인증을 시도(token값과 User정보 조회)해서 인증객체를 가질 수 있도록 이 필터가 작동한다
 * 새로운 인증객체가 생성되면 다시 AuthenticationManager가 인증처리를 함
 *  chain.doFilter => FilterChain에 여러개의 필터가 등록되어 있고 한 필터를 거친 다음 필터로 가는 방식
 *
 *  SecurityContext 객체 안에 Authentication 객체가 없으면 AnonymousAuthenticationFilter 가 작동해서
 *  익명인증객체(Anonymous AuthenticationToken)을 생성한다, 익명인증객체는 세션에 저장되지 않는다. isAnonymous() = true인 경우
 *  로그인 페이지로 redirect 하는 로직.
 *
 * 스프링 컨테이너는 @Configuration이 붙어있는 클래스를 자동으로 빈으로 등록해두고, 해당 클래스를 파싱해서 @Bean이 있는 메소드를 찾아서 빈을 생성해준다.
 * 생성된 Bean의 이름은 메소드명과 동일하다
 * https://mangkyu.tistory.com/75
 *
 * HttpSecurity 객체로 설정한 api의 종류에 따라 SecurityFilterChain에 담긴 filters 구성 종류가 달라짐.
 * 사용자의 요청을 가장 먼저 받는 부분 :FitlerChainProxy
 * FitlerChainProxy는 SecurityFilterChains 안에 여러개의 필터체인을 가지고 있고, 각 필터체인은 여러개의 필터 목록으로 구성되어 있다
 * 요청을 받은 직후 필터체인의 여러개의 필터들을 호출하면서 각 필터들에게 해당 요청을 처리하게 하는 로직이다.
 *
 * 설정 값 우선순위 : @EnableWebSecurity가 적용된 class > applictaion.yml or properties
 **/
//순환 참조 문제때문에 userDetailService 안쓸때는 잠시 주석처리
//    private final UserDetailsService userDetailService;
    @Order(1)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // 소스 코드에 직접 인가,인증 설정을 하는 선언적 방식 
        // 실전 프로젝트에는 동적으로 바꿀 예정
        http
                .authorizeRequests()
//                .antMatchers("/login").permitAll() // 로그인 페이지는 인증,인가받지 않아도 접근할 수 있도록 함
//                .antMatchers("/user").hasRole("USER") //특정 자원의 경로에 대해 특정 권한이 있는지 검사하는 부분
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated();
                .anyRequest().permitAll()
                .and()
        
                .formLogin() //인증방식 : formLogin api
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        SavedRequest savedRequest = requestCache.getRequest(request, response); // 인증 전에 사용자가 가고자 했던 자원에 대한 정보(경로..)가 request에 저장되어 있음
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        response.sendRedirect(redirectUrl);
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception:"+exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll()
        ;
//        http
//                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() { //인증예외 발생시 처리함
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() { // 인가예외 발생시 처리함
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        response.sendRedirect("/denied");
//                    }
//                })
//        http
//                .logout() // default method : post
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me")
//            .and()
//                .rememberMe() // rememberMe 기능 활성화
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600) // 초 단위 , 1시간
//                .userDetailsService(userDetailService);
//        http
//                .sessionManagement() // 동시 세션 제어 API
//                .sessionFixation().changeSessionId() //default가 changeSessionId, 인증할 때마다 세션 쿠키를 새로 발급(jsessionid가 변함)하여 공격자의 쿠키 조작을 방지
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true) //true:기존 세션자가 인증을 우선으로 가진다 , false:가장 최근의 사용자가 인증권을 우선으로 가짐
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        /**
         * 부모 스레드와 자식 스레드 간 인증 객체 공유 가능하게 설정
         */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL); 
        return http.build();
    }
    // 다중 config 설정 추가
    @Order(0)
    @Bean
    public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception{
        http
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
            .and()
                .httpBasic();// 해석 : /admin 하위로 요청했을때 다음과같이 요청에 인가를 한다. 어떤 요청이든지 인증되어 있어야 한다. 인증 api는 httpBasic 이다 .
        // httpBasic의 인증 값은 application.properties에 선언한 값이 default 인 듯.
        return http.build();
    }

    // In-memory 방식으로 User 생성 해보기
    @Bean
    public UserDetailsManager users(){
        // Spring secuirty 암호화 기능에서 어떤 암호화 방식을 사용했는지 password 앞의 {}안에 넣는다. 아무것도 사용하지 않았으면 noop 사용
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}1111")
                .roles("SYS","USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}1111")
                .roles("ADMIN","SYS","USER") // In-memory 방식이 아닐 때는 Role Hierarchy로 권한계층을 설정할 수 있다 (admin이 다른 권한을 포함하는 것 처럼?)
                .build();
        return new InMemoryUserDetailsManager(user,sys,admin);
    }

}
