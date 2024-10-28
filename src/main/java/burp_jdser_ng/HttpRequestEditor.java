package burp_jdser_ng;

import javax.management.RuntimeErrorException;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

class HttpRequestEditor extends BaseEditor implements ExtensionProvidedHttpRequestEditor {

    HttpRequestEditor(MontoyaApi api, EditorCreationContext creationContext, JDSer jdSer) {
        super(api, creationContext, jdSer);
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        payload = requestResponse.request().body().getBytes();
        return jdSer.isSerialized(payload);
    }

    @Override
    public HttpRequest getRequest() {
        HttpRequest request = requestResponse.request();

        if (editor.isModified()) {
            throw new RuntimeErrorException(null, editor.getContents().toString());
            // return request.withBody(jdSer.Deserialize(editor.getContents().toString()));
        }

        return request;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;

        payload = requestResponse.request().body().getBytes();
        editor.setContents(jdSer.ByteArrayToXML(payload, jdSer.customClassLoader));
    }
}
