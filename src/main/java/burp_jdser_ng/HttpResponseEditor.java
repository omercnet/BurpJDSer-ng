package burp_jdser_ng;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

class HttpResponseEditor extends BaseEditor implements ExtensionProvidedHttpResponseEditor {

    HttpResponseEditor(MontoyaApi api, EditorCreationContext creationContext, JDSer jdSer) {
        super(api, creationContext, jdSer);

    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        payload = requestResponse.response().body().getBytes();
        return jdSer.isSerialized(payload);
    }

    @Override
    public HttpResponse getResponse() {
        HttpResponse response = requestResponse.response();

        if (editor.isModified()) {
            return response.withBody(jdSer.XMLToByteArray(editor.getContents().toString()));
        }

        return response;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;

        payload = requestResponse.response().body().getBytes();
        editor.setContents(jdSer.ByteArrayToXML(payload, jdSer.customClassLoader));
    }
}
