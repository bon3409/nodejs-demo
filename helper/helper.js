module.exports = {
    coverTimeFormat: function(timestamp) {
        dateFormat = new Date(parseInt(timestamp));
        return dateFormat.getFullYear()+
           "-"+String((dateFormat.getMonth()+1)).padStart(2, '0')+
           "-"+String(dateFormat.getDate()).padStart(2, '0')+
           " "+String(dateFormat.getHours()).padStart(2, '0')+
           ":"+String(dateFormat.getMinutes()).padStart(2, '0')+
           ":"+String(dateFormat.getSeconds()).padStart(2, '0');
    }
}