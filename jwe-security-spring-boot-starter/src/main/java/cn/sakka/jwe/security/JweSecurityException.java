package cn.sakka.jwe.security;

public class JweSecurityException extends RuntimeException {

    public JweSecurityException() {
    }

    public JweSecurityException(String message) {
        super(message);
    }

    public JweSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

    public JweSecurityException(Throwable cause) {
        super(cause);
    }

    public JweSecurityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
