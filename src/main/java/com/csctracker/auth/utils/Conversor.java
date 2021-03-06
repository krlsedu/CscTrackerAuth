package com.csctracker.auth.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.List;
import java.util.stream.Collectors;

public class Conversor<U, T> {
    private final ObjectMapper objectMapper;
    private final Class<U> uClass;
    private final Class<T> tClass;

    public Conversor(Class<U> uClass, Class<T> tClass) {
        this.uClass = uClass;
        this.tClass = tClass;
        objectMapper = new ObjectMapper()
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(SerializationFeature.WRITE_DATES_WITH_ZONE_ID, false)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public List<U> toU(List<T> ts) {
        return ts.stream().map(this::toU).collect(Collectors.toList());
    }

    public U toU(T t) {
        return objectMapper.convertValue(t, uClass);
    }

    public List<T> toT(List<U> us) {
        return us.stream().map(this::toT).collect(Collectors.toList());
    }

    public T toT(U u) {
        return objectMapper.convertValue(u, tClass);
    }

    public T toT(String t) throws JsonProcessingException {
        return objectMapper.readValue(t, tClass);
    }

    public T toT(String t, Class clazz) {
        return objectMapper.convertValue(t, tClass);
    }

    public ObjectMapper getObjectMapper() {
        return objectMapper;
    }
}