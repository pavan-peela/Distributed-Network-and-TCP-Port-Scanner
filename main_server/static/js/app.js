console.log('App.js!');

var triggerOperation = function() {
  let optionSelected = $("#first_drop").val()
  console.log(optionSelected);

  if ( optionSelected === 'port_scan' ) {
    $('#portScan').css('display', 'block');
  } else {
    $('#portScan').css('display', 'none');
  }
}

$('first_drop').on('change', function(){
	document.getElementById('result').style.display = "none";
});

