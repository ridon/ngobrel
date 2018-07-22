package id.ngobrel.core;

public class EncryptionFailedException extends Exception {

    String message;

    public EncryptionFailedException(String s) {
        message = s;
    }

    public EncryptionFailedException() {

    }

    @Override
    public String getMessage() {
        if (message.isEmpty()) return super.getMessage();
        return message;
    }
}
