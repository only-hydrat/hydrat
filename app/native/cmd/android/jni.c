#include <jni.h>
#include <stdlib.h>
#include <string.h>

extern int hydratOpen(char *, char *, char *, char *);
extern char *hydratImport(char *, int, char *);
extern char *hydratStatus(void);
extern char *hydratRefresh(void);
extern char *hydratCheckUpdate(void);
extern char *hydratImportSuggested(void);
extern int hydratPrepare(void);
extern int hydratRun(int, int, int, char *);
extern int hydratRemoveSource(char *);
extern int hydratSetHWID(char *);
extern char *hydratSetSourceHWID(char *, char *);
extern char *hydratSourceHWID(char *);
extern char *hydratGeoSettings(void);
extern char *hydratSaveGeoSettings(char *);
extern void hydratSetScreenInteractive(int);
extern void hydratStop(void);

JNIEXPORT jint JNICALL Java_org_hydrat_app_NativeEngine_open(
    JNIEnv *env, jobject object, jstring root, jstring tor, jstring transport, jstring assets) {
    const char *root_value = (*env)->GetStringUTFChars(env, root, NULL);
    const char *tor_value = (*env)->GetStringUTFChars(env, tor, NULL);
    const char *transport_value = (*env)->GetStringUTFChars(env, transport, NULL);
    const char *assets_value = (*env)->GetStringUTFChars(env, assets, NULL);
    int result = 1;
    if (root_value && tor_value && transport_value && assets_value) {
        result = hydratOpen((char *)root_value, (char *)tor_value, (char *)transport_value, (char *)assets_value);
    }
    if (assets_value) (*env)->ReleaseStringUTFChars(env, assets, assets_value);
    if (transport_value) (*env)->ReleaseStringUTFChars(env, transport, transport_value);
    if (tor_value) (*env)->ReleaseStringUTFChars(env, tor, tor_value);
    if (root_value) (*env)->ReleaseStringUTFChars(env, root, root_value);
    return result;
}

static jstring take_string(JNIEnv *env, char *value) {
    if (value == NULL) return NULL;
    jstring result = (*env)->NewStringUTF(env, value);
    free(value);
    return result;
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_importSources(JNIEnv *env, jobject object, jbyteArray input, jstring hwid) {
    jsize size = (*env)->GetArrayLength(env, input);
    if (size == 0 || size > 4*1024*1024) return NULL;
    char *copy = malloc((size_t)size);
    if (copy == NULL) return NULL;
    (*env)->GetByteArrayRegion(env, input, 0, size, (jbyte *)copy);
    const char *value = (*env)->ExceptionCheck(env) ? NULL : (*env)->GetStringUTFChars(env, hwid, NULL);
    char *result = value == NULL ? NULL : hydratImport(copy, size, (char *)value);
    if (value != NULL) (*env)->ReleaseStringUTFChars(env, hwid, value);
    free(copy);
    return take_string(env, result);
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_setSourceHWID(
    JNIEnv *env, jobject object, jstring id, jstring hwid) {
    const char *source = (*env)->GetStringUTFChars(env, id, NULL);
    if (source == NULL) return NULL;
    const char *value = (*env)->GetStringUTFChars(env, hwid, NULL);
    char *result = value == NULL ? NULL : hydratSetSourceHWID((char *)source, (char *)value);
    if (value != NULL) (*env)->ReleaseStringUTFChars(env, hwid, value);
    (*env)->ReleaseStringUTFChars(env, id, source);
    return take_string(env, result);
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_sourceHWID(
    JNIEnv *env, jobject object, jstring id) {
    const char *source = (*env)->GetStringUTFChars(env, id, NULL);
    if (source == NULL) return NULL;
    char *result = hydratSourceHWID((char *)source);
    (*env)->ReleaseStringUTFChars(env, id, source);
    return take_string(env, result);
}

JNIEXPORT jbyteArray JNICALL Java_org_hydrat_app_NativeEngine_status(JNIEnv *env, jobject object) {
    char *value = hydratStatus();
    if (value == NULL) return NULL;
    jsize length = (jsize)strlen(value);
    jbyteArray result = (*env)->NewByteArray(env, length);
    if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, length, (const jbyte *)value);
    free(value);
    return result;
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_refreshSources(JNIEnv *env, jobject object) {
    return take_string(env, hydratRefresh());
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_checkUpdate(JNIEnv *env, jobject object) {
    return take_string(env, hydratCheckUpdate());
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_importSuggested(JNIEnv *env, jobject object) {
    return take_string(env, hydratImportSuggested());
}

JNIEXPORT jboolean JNICALL Java_org_hydrat_app_NativeEngine_removeSource(JNIEnv *env, jobject object, jstring id) {
    const char *value = (*env)->GetStringUTFChars(env, id, NULL);
    if (value == NULL) return JNI_FALSE;
    int result = hydratRemoveSource((char *)value);
    (*env)->ReleaseStringUTFChars(env, id, value);
    return result == 0;
}

JNIEXPORT jboolean JNICALL Java_org_hydrat_app_NativeEngine_setHWID(JNIEnv *env, jobject object, jstring hwid) {
    const char *value = (*env)->GetStringUTFChars(env, hwid, NULL);
    if (value == NULL) return JNI_FALSE;
    int result = hydratSetHWID((char *)value);
    (*env)->ReleaseStringUTFChars(env, hwid, value);
    return result == 0;
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_geoSettings(JNIEnv *env, jobject object) {
    return take_string(env, hydratGeoSettings());
}

JNIEXPORT jstring JNICALL Java_org_hydrat_app_NativeEngine_saveGeoSettings(
    JNIEnv *env, jobject object, jstring settings) {
    const char *value = (*env)->GetStringUTFChars(env, settings, NULL);
    if (value == NULL) return NULL;
    char *result = hydratSaveGeoSettings((char *)value);
    (*env)->ReleaseStringUTFChars(env, settings, value);
    return take_string(env, result);
}

JNIEXPORT void JNICALL Java_org_hydrat_app_NativeEngine_setScreenInteractive(JNIEnv *env, jobject object, jboolean interactive) {
    hydratSetScreenInteractive(interactive);
}

JNIEXPORT jint JNICALL Java_org_hydrat_app_NativeEngine_run(
    JNIEnv *env, jobject object, jint fd, jint dns, jboolean geo, jstring settings) {
    const char *value = (*env)->GetStringUTFChars(env, settings, NULL);
    if (value == NULL) return 1;
    int result = hydratRun(fd, dns, geo, (char *)value);
    (*env)->ReleaseStringUTFChars(env, settings, value);
    return result;
}

JNIEXPORT jint JNICALL Java_org_hydrat_app_NativeEngine_prepare(JNIEnv *env, jobject object) {
    return hydratPrepare();
}

JNIEXPORT void JNICALL Java_org_hydrat_app_NativeEngine_stop(JNIEnv *env, jobject object) {
    hydratStop();
}
