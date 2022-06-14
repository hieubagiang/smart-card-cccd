



import java.util.Date;

/**
 *
 * @author phamb
 */
public class UserModel {
        private String cardId;
        private String pin;

        private String avatarImage;
        private String fingerPrintImage;

        private String fullName;
        private String address;
        private byte sex;
        private String region;
        private String national;
        private String birthday;

        private String expiredDate;
        private String releaseDate;

        private String note;
        private long amount;

    public UserModel() {
        
    }

    public UserModel(String cardId, 
            String pin, String avatarImage, String fingerPrintImage, 
            String fullName, String address, byte sex, String region, 
            String national, String birthday, String expiredDate, 
            String releaseDate, String note, long amount) {
        this.cardId = cardId;
        this.pin = pin;
        this.avatarImage = avatarImage;
        this.fingerPrintImage = fingerPrintImage;
        this.fullName = fullName;
        this.address = address;
        this.sex = sex;
        this.region = region;
        this.national = national;
        this.birthday = birthday;
        this.expiredDate = expiredDate;
        this.releaseDate = releaseDate;
        this.note = note;
        this.amount = amount;
    }

    public String getCardId() {
        return cardId;
    }

    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getAvatarImage() {
        return avatarImage;
    }

    public void setAvatarImage(String avatarImage) {
        this.avatarImage = avatarImage;
    }

    public String getFingerPrintImage() {
        return fingerPrintImage;
    }

    public void setFingerPrintImage(String fingerPrintImage) {
        this.fingerPrintImage = fingerPrintImage;
    }

    public String getFullname() {
        return fullName;
    }

    public void setFullname(String fullname) {
        this.fullName = fullname;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public byte getSex() {
        return sex;
    }

    public void setSex(byte sex) {
        this.sex = sex;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getNational() {
        return national;
    }

    public void setNational(String national) {
        this.national = national;
    }

    public String getBirthday() {
        return birthday;
    }

    public void setBirthday(String birthday) {
        this.birthday = birthday;
    }

    public String getExpiredDate() {
        return expiredDate;
    }

    public void setExpiredDate(String expiredDate) {
        this.expiredDate = expiredDate;
    }

    public String getReleaseDate() {
        return releaseDate;
    }

    public void setReleaseDate(String releaseDate) {
        this.releaseDate = releaseDate;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public long getAmount() {
        return amount;
    }

    public void setAmount(long amount) {
        this.amount = amount;
    }

    @Override
    public String toString() {
        return  cardId + "." + pin + "." + "." + "." + fullName + "." + address 
                + "." + sex + "." + region + "." + national + "." + birthday 
                + "." + expiredDate + "." + releaseDate + "." + note + "." + amount;
    }
}
