//package com.regverse.apigw.security;
//
//
//import lombok.Data;
//import org.springframework.security.access.AuthorizationServiceException;
//import org.springframework.stereotype.Component;
//
//import java.util.List;
//import java.util.UUID;
//
//@Component
//@Data
//public class RequestUser {
//
//    private UUID id;
//    private String country;
//    private List<String> appUserAuthorities;
//
////    private AppUserDetails getRequestUser(){
////        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
////        return (AppUserDetails) token.getPrincipal();
////    }
////    public AppUser getRequestAppUser(){
////        return getRequestUser().getAppUser();
////    }
////
////    public Collection<? extends GrantedAuthority> getRequestAppUserAuthorities(){
////        return getRequestUser().getAuthorities();
////    }
//
//    public UUID getAppUserId(){
//        return this.id;
//    }
//
//    public String getRequestAppUserCountryName() {
//        return this.country;
//    }
//
//    public void checkAuthorization(String country) /*<-- check this with the request user country*/{
//        if(this.appUserAuthorities
//                .stream().noneMatch(s -> s.contains("Admin")) ) {
//            throw new AuthorizationServiceException("Access denied -- you have no permission on this");
//        }
//
//        if(isNormalAdmin() && !getRequestAppUserCountryName().equals(country)) {
//            throw new AuthorizationServiceException("Access denied -- you have no permission on this");
//        }
//    }
//
//    public boolean isAdmin() {
//        return isNormalAdmin() || isSuperAdmin();
//    }
//
//    public boolean isNormalAdmin() {
//        return appUserAuthorities.stream().anyMatch(s -> s.contains("Admin"));
//    }
//
//    public boolean isSuperAdmin() {
//        return appUserAuthorities.stream().anyMatch(s -> s.equals("GlobalAdmin"));
//    }
//}
