package com.adioss.security;

import java.security.Provider;
import java.util.*;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

public class ProviderDescriptor {
    public static void main(String... args) {
        ProviderList fullProviderList = Providers.getFullProviderList();
        List<Provider> providers = fullProviderList.providers();
        for (Provider provider : providers) {
            System.out.println(">>>>>>>>>>>>>>>  " + provider.getInfo());
            Set<Provider.Service> services = provider.getServices();
            for (Provider.Service service : services) {

                System.out.println(service.getAlgorithm() + service.getType());
            }
        }
    }
}
