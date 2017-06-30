package br.com.paulork.securityutils.exception;

/**
 * @author Paulo R. Kraemer <paulork10@gmail.com>
 */
public class SecurityUtilsException extends Exception {

    public SecurityUtilsException(String message) {
        super(message);
    }
    
    public SecurityUtilsException(Throwable throwable) {
        super(throwable);
    }
    
    public SecurityUtilsException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
