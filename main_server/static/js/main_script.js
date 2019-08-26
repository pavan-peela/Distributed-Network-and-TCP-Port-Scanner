console.log("Main Script.js")
var scan_progress = false;

$(document).ready(function() {
    // Past Scans Button Action
    $( "#past" ).click(function() {
        var win = window.open('/pastScans', '_blank');
        if (win) {
            win.focus();
        } else {
            alert('Please allow popups for this website');
        }
    });
    // Checkbox on Ckecked Action
    $("input[type='checkbox']").on('change', function(){
    $(this).val(this.checked ? "TRUE" : "FALSE");
    });
});

$(document).ready( function() {
    // Hiding of Validation Error Scripts
    $('.ip_none').hide();
    $('.port_none').hide();
    
    // On Button Click
    $('#submit').click(function() {
        // console.log("inside submit click");
        $('.ip_none').hide();
        $('.port_none').hide();
        $( "p" ).remove();
        // Multiple Scan Blocking
        if(scan_progress == true){
            $( "p" ).remove();
            var get_div = document.getElementById("out");
            var newElement = document.createElement( "p" );
            newElement.innerHTML = "Please Wait! Scan in Progress ....";
            get_div.append(newElement);
            return;
        }
        ip = document.getElementById('ip_input');
        var rand = document.getElementById('defaultCheck1');
        

        var mode = document.getElementById('first_drop').value;
        // console.log(mode)
        por = document.getElementById('port_input');

        // Validation Checks
        if(mode == 'ip_alive'){
            if (typeof ip.value === 'undefined' || ip.value == ""){
                console.log('IP Null -> Retry')
                $('.ip_none').show();
                return;
            }
        }
        else if(mode == 'port_scan'){
            if(typeof por.value === 'undefined' || por.value == ""){
                if (typeof ip.value === 'undefined' || ip.value == ""){
                    console.log('IP and Port Null -> Retry')
                    $('.ip_none').show();
                    $('.port_none').show();
                    return;
                }
                else{
                    console.log('Port Null -> Retry')
                    $('.port_none').show();
                    // $('.port_none')
                    return;
                }
            }
        }

        // Ajax Call
        var destURL = getURL(mode);
        // console.log(destURL);
        var formdata = serialize(mode, rand.value);
        // console.log(formdata);
        scan_progress = !scan_progress;
        // console.log('scan progess Before AJAX CALL',scan_progress);
        $.ajax({
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(formdata),
            dataType: 'json',
            url: destURL,
            success: function (e) {
                    $( "p" ).remove();
                    scan_progress = !scan_progress;
                    document.getElementById('result').style.display = "block";
                    checkscript(e);
            },
            error: function(error) {
                console.log(error);
            }
        });
    });
});

// Displaying the result on the UI
function checkscript(obj) {
    if (obj) {
        var scan_status = "";
        var get_div = document.getElementById("out");
        i = 0;
        Object.keys(obj).forEach(function(key) {
   
            if (i==0){
                scan_status = obj[key];
                var newElement = document.createElement( "p" );
                newElement.innerHTML = 'Scan Result :';
                get_div.append(newElement);
            }
            if (i==1){
                if (scan_status){
                    temp = obj[key];
                    Object.keys(temp).forEach(function(key){
                        key_ip = key
                        key_ip_result = temp[key];

                        let template = `
                            <p class='row'>
                                <span class='col-3'></span>
                                <span class='key col-3'>${key_ip}</span>
                                <span class='value col-3'>${key_ip_result}</span>
                                <span class='col-3'></span>
                            </p>`

                        $("#out").append(template);
                    });
                }
                else{
                    var newElement = document.createElement( "p" );
                    newElement.innerHTML = 'Scan Failed!!';
                    get_div.append(newElement);
                }
            }
            i = i+1;
        });
    } else {
        alert('Object Structure wrong!');
    }
}
// Get the routing Address 
function getURL(val){
    if(val == 'ip_alive')return '/checkIP';
    else if(val == 'ip_subnet')return '/checkIPSubnet';
    else if(val == 'port_scan')return '/portScan';
}

// JSON object Creation
function serialize(val, seq){
    var ret = new Object();
    if(val == 'ip_alive')ret.mode = 1;
    else if(val == 'ip_subnet')ret.mode = 2;
    else if(val == 'port_scan')ret.mode = 3;

    ret.ip = document.getElementById('ip_input').value;

    if(ret.mode == 3){
        ret.type = document.getElementById('scanning_type').value;
        ret.portRange = document.getElementById('port_input').value;
    }
    ret.random = seq;

    return ret;
}
