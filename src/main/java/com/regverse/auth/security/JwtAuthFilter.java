//package com.regverse.apigw.security;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//@RequiredArgsConstructor
//public class JwtAuthFilter extends OncePerRequestFilter {
//
//    private final UserDetailsService userDetailsService;
//    private final JwtUtils jwtUtil;
//
//    private final RequestUser requestUser;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//        final String authHeader = request.getHeader("Authorization");
//        final String email;
//        final String jwtToken;
//
//        if (authHeader == null || !authHeader.startsWith("Bearer ")){
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        jwtToken = authHeader.substring(7);
//        email = jwtUtil.extractUsername(jwtToken);
//
//        if( email != null && SecurityContextHolder.getContext().getAuthentication() == null){
//
//            UserDetails userDetails = userDetailsService.loadUserByUsername(email);
//
//            if (jwtUtil.validateToken(jwtToken, userDetails)) {
//                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
//                    userDetails, null, userDetails.getAuthorities());
//                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(token);
//
////                requestUser.setCountry(jwtUtil.extractClaim(jwtToken, (map)->map.get("Country")).toString());
////                requestUser.setAppUserAuthorities(jwtUtil.extractClaim(jwtToken, (map)->map.get("Role")));
//
//            }
//            filterChain.doFilter(request, response);
//
//        }
//
//    }
//}
