const et = require('elementtree');
const path = require('path');
const fs = require('fs');
const { ConfigParser } = require('cordova-common');

module.exports = function (context) {
    var projectRoot = context.opts.cordova.project ? context.opts.cordova.project.root : context.opts.projectRoot;
    var configXML = path.join(projectRoot, 'config.xml');
    var configParser = new ConfigParser(configXML);
    var authenticate = configParser.getGlobalPreference("MigratedValuesAuthentication");
    console.log("AUTHENTICATE: " + authenticate);
    

    if(authenticate == "true"){
        console.log("ENTROU NO TRUE");
        var stringsXmlPath = path.join(projectRoot, 'platforms/android/app/src/main/res/values/strings.xml');
        var stringsXmlContents = fs.readFileSync(stringsXmlPath).toString();
        var etreeStrings = et.parse(stringsXmlContents);

        var migrationAuthTags = etreeStrings.findall('./bool[@name="migration_auth"]');
        for (var i = 0; i < migrationAuthTags.length; i++) {
            migrationAuthTags[i].text = authenticate;
        }

        var resultXmlStrings = etreeStrings.write();
        fs.writeFileSync(stringsXmlPath, resultXmlStrings);
    }
};
