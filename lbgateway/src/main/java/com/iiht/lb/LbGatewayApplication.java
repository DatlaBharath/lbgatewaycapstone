package com.iiht.lb;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

//@EnableDiscoveryClient
@EnableFeignClients
@SpringBootApplication
public class LbGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(LbGatewayApplication.class, args);
	}

}
