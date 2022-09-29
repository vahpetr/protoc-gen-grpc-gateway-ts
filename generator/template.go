package generator

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"

	"github.com/Masterminds/sprig"
	"github.com/iancoleman/strcase"

	"github.com/grpc-ecosystem/protoc-gen-grpc-gateway-ts/data"
	"github.com/grpc-ecosystem/protoc-gen-grpc-gateway-ts/registry"
)

const tmpl = `
{{define "dependencies"}}
{{range .}}import * as {{.ModuleIdentifier}} from "{{.SourceFile}}"
{{end}}{{end}}

{{define "enums"}}
{{range .}}export enum {{.Name}} {
{{- range .Values}}
  {{.}} = "{{.}}",
{{- end}}
}

{{end}}{{end}}
{{define "messages"}}{{range .}}
export type {{.Name}} = {
{{- range .Fields}}
  {{fieldName .Name}}{{tsUndefined .}}: {{tsType .}}
{{- end}}
}
{{end}}{{end}}

{{define "services"}}{{range .}}
export class {{.Name}}Client {
  constructor(protected _host, protected _token) {}
  public set token(token: string) {
    this._token = token
  }
{{- range .Methods}}
{{- if .ServerStreaming }}
  {{.Name}} = (req: {{tsType .Input}}, next?: fm.StreamNext<{{tsType .Output}}>, init?: RequestInit): Promise<void> => {
    return fm.stream<{{tsType .Input}}, {{tsType .Output}}>(` + "`${this._host}{{renderURL .}}`" + `, next, {...init, {{buildInitReq .}}, ...{ headers: { ...init?.headers, ...{ 'Authorization': ` + "`Bearer ${this._token}`" + ` } } }})
  }
{{- else }}
  {{.Name}} = (req: {{tsType .Input}}, init?: RequestInit): Promise<{{tsType .Output}}> => {
    return fm.request<{{tsType .Input}}, {{tsType .Output}}>(` + "`${this._host}{{renderURL .}}`" + `, {...init, {{buildInitReq .}}, ...{ headers: { ...init?.headers, ...{ 'Authorization': ` + "`Bearer ${this._token}`" + ` } } } })
  }
{{- end}}
{{- end}}
}
{{end}}{{end}}

{{- if not .EnableStylingCheck}}
/* eslint-disable */
// @ts-nocheck
{{- end}}
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/
{{if .Dependencies}}{{- include "dependencies" .StableDependencies -}}{{end}}
{{- if .Enums}}{{include "enums" .Enums}}{{end}}
{{- if .Messages}}{{include "messages" .Messages}}{{end}}
{{- if .Services}}{{include "services" .Services}}{{end}}

`

const fetchTmpl = `
{{- if not .EnableStylingCheck}}
/* eslint-disable */
// @ts-nocheck
{{- end}}
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

/**
 * base64 encoder and decoder
 * Copied and adapted from https://github.com/protobufjs/protobuf.js/blob/master/lib/base64/index.js
 */
// Base64 encoding table
const b64 = new Array(64);

// Base64 decoding table
const s64 = new Array(123);

// 65..90, 97..122, 48..57, 43, 47
for (let i = 0; i < 64;)
    s64[b64[i] = i < 26 ? i + 65 : i < 52 ? i + 71 : i < 62 ? i - 4 : i - 59 | 43] = i++;

export function b64Encode(buffer: Uint8Array, start: number, end: number): string {
	let parts: string[] = null;
  const chunk = [];
  let i = 0, // output index
    j = 0, // goto index
    t;     // temporary
  while (start < end) {
    const b = buffer[start++];
    switch (j) {
      case 0:
        chunk[i++] = b64[b >> 2];
        t = (b & 3) << 4;
        j = 1;
        break;
      case 1:
        chunk[i++] = b64[t | b >> 4];
        t = (b & 15) << 2;
        j = 2;
        break;
      case 2:
        chunk[i++] = b64[t | b >> 6];
        chunk[i++] = b64[b & 63];
        j = 0;
        break;
    }
    if (i > 8191) {
      (parts || (parts = [])).push(String.fromCharCode.apply(String, chunk));
      i = 0;
    }
  }
  if (j) {
    chunk[i++] = b64[t];
    chunk[i++] = 61;
    if (j === 1)
      chunk[i++] = 61;
  }
  if (parts) {
    if (i)
      parts.push(String.fromCharCode.apply(String, chunk.slice(0, i)));
    return parts.join("");
  }
  return String.fromCharCode.apply(String, chunk.slice(0, i));
}

const invalidEncoding = "invalid encoding";

export function b64Decode(s: string): Uint8Array {
	const buffer = [];
	let offset = 0;
  let j = 0, // goto index
      t;     // temporary
  for (let i = 0; i < s.length;) {
    let c = s.charCodeAt(i++);
    if (c === 61 && j > 1)
        break;
    if ((c = s64[c]) === undefined)
        throw Error(invalidEncoding);
    switch (j) {
      case 0:
        t = c;
        j = 1;
        break;
      case 1:
        buffer[offset++] = t << 2 | (c & 48) >> 4;
        t = c;
        j = 2;
        break;
      case 2:
        buffer[offset++] = (t & 15) << 4 | (c & 60) >> 2;
        t = c;
        j = 3;
        break;
      case 3:
        buffer[offset++] = (t & 3) << 6 | c;
        j = 0;
        break;
    }
  }
  if (j === 1)
      throw Error(invalidEncoding);
  return new Uint8Array(buffer);
}

export function replacer(_: any, value: any): any {
  if (value && value.constructor === Uint8Array) {
    return b64Encode(value, 0, value.length);
  }

  return value;
}

export async function request<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const result = await fetch<T>(input, init)
  if (!result.ok) {
    const response = await result.json()
    const message = response.error && response.error.message
      ? response.error.message
      : response
    throw new Error(message)
  }

  if (!result.body) {
    return;
  }

  const response = await result.json()

  return response;
}

export type ApiError = {
  code: number
  message: string
  details: ApiErrorDetail[]
}

export type ApiErrorDetail = {
  [key: string]: string
}

export type StreamResponse<T> = {
  result?: T
  error?: ApiError
}

export type StreamNext<T> = (response: StreamResponse<T>) => void

export async function stream<T>(input: RequestInfo | URL, next?: StreamNext<T>, init?: RequestInit) {
  const result = await fetch(input, init)
  if (!result.ok) {
    const response = await result.json()
    const message = response.error && response.error.message
      ? response.error.message
      : response
    throw new Error(message)
  }

  if (!result.body) {
    return;
  }

  const textDecoderStream = new TextDecoderStream()
  const jsonDecoderStream = CreateJsonDecoderStream<StreamResponse<T>>(next)
  // const nextWritableStream = NextWritableStream(next)

  await result.body
      .pipeThrough(textDecoderStream)
      .pipeThrough<StreamResponse<T>>(jsonDecoderStream)
      // .pipeTo(nextWritableStream)
      .pipeTo(new WritableStream())
}

interface JsonStringStreamController<T> extends TransformStreamDefaultController {
  buf?: string
  pos?: number
  enqueue: (response: T) => void
}

function CreateJsonDecoderStream<T>(next: StreamNext<T>): TransformStream<string, T> {
  return new TransformStream({
    start(controller: JsonStringStreamController<T>) {
      controller.buf = ''
      controller.pos = 0
    },

    transform(chunk: string, controller: JsonStringStreamController<T>) {
      if (controller.buf === undefined) {
        controller.buf = ''
      }
      if (controller.pos === undefined) {
        controller.pos = 0
      }
      controller.buf += chunk
      while (controller.pos < controller.buf.length) {
        if (controller.buf[controller.pos] === '\n') {
          const line = controller.buf.substring(0, controller.pos)
          if (line != '[' && line != ',' && line != ']') {
            const response = JSON.parse(line)
            // controller.enqueue(response)
            next && next(response)
          }
          controller.buf = controller.buf.substring(controller.pos + 1)
          controller.pos = 0
        } else {
          ++controller.pos
        }
      }
    }
  })
}

// function CallbackWritableStream<T>(next: StreamNext<T>) {
//   return new WritableStream<T>({
//     write(response: T) {
//       next && next(response)
//     }
//   })
// }

type Primitive = string | boolean | number;
type RequestPayload = Record<string, unknown>;
type FlattenedRequestPayload = Record<string, Primitive | Array<Primitive>>;

/**
 * Checks if given value is a plain object
 * Logic copied and adapted from below source:
 * https://github.com/char0n/ramda-adjunct/blob/master/src/isPlainObj.js
 * @param  {unknown} value
 * @return {boolean}
 */
function isPlainObject(value: unknown): boolean {
  const isObject =
    Object.prototype.toString.call(value).slice(8, -1) === "Object";
  const isObjLike = value !== null && isObject;

  if (!isObjLike || !isObject) {
    return false;
  }

  const proto = Object.getPrototypeOf(value);

  const hasObjectConstructor =
    typeof proto === "object" &&
    proto.constructor === Object.prototype.constructor;

  return hasObjectConstructor;
}

/**
 * Checks if given value is of a primitive type
 * @param  {unknown} value
 * @return {boolean}
 */
function isPrimitive(value: unknown): boolean {
  return ["string", "number", "boolean"].some(t => typeof value === t);
}

/**
 * Checks if given primitive is zero-value
 * @param  {Primitive} value
 * @return {boolean}
 */
function isZeroValuePrimitive(value: Primitive): boolean {
  return value === false || value === 0 || value === "";
}

/**
 * Flattens a deeply nested request payload and returns an object
 * with only primitive values and non-empty array of primitive values
 * as per https://github.com/googleapis/googleapis/blob/master/google/api/http.proto
 * @param  {RequestPayload} requestPayload
 * @param  {String} path
 * @return {FlattenedRequestPayload}
 */
function flattenRequestPayload<T extends RequestPayload>(
  requestPayload: T,
  path: string = ""
): FlattenedRequestPayload {
  return Object.keys(requestPayload).reduce(
    (acc: T, key: string): T => {
      const value = requestPayload[key];
      const newPath = path ? [path, key].join(".") : key;

      const isNonEmptyPrimitiveArray =
        Array.isArray(value) &&
        value.every(v => isPrimitive(v)) &&
        value.length > 0;

      const isNonZeroValuePrimitive =
        isPrimitive(value) && !isZeroValuePrimitive(value as Primitive);

      let objectToMerge = {};

      if (isPlainObject(value)) {
        objectToMerge = flattenRequestPayload(value as RequestPayload, newPath);
      } else if (isNonZeroValuePrimitive || isNonEmptyPrimitiveArray) {
        objectToMerge = { [newPath]: value };
      }

      return { ...acc, ...objectToMerge };
    },
    {} as T
  ) as FlattenedRequestPayload;
}

export function buildQuery<T extends RequestPayload>(
  requestPayload: T,
  urlPathParams: string[] = []
): string {
  const flattenedRequestPayload = flattenRequestPayload(requestPayload);

  const urlSearchParams = Object.keys(flattenedRequestPayload).reduce(
    (acc: string[][], key: string): string[][] => {
      // key should not be present in the url path as a parameter
      const value = flattenedRequestPayload[key];
      if (urlPathParams.find(f => f === key)) {
        return acc;
      }
      return Array.isArray(value)
        ? [...acc, ...value.map(p => [key, p.toString()])]
        : (acc = [...acc, [key, value.toString()]]);
    },
    [] as string[][]
  );

  const query = new URLSearchParams(urlSearchParams).toString();
  return query ? ("?" + query) : ""
}

`

// GetTemplate gets the templates to for the typescript file
func GetTemplate(r *registry.Registry) *template.Template {
	t := template.New("file")
	t = t.Funcs(sprig.TxtFuncMap())

	t = t.Funcs(template.FuncMap{
		"include": include(t),
		"tsType": func(fieldType data.Type) string {
			return tsType(r, fieldType)
		},
		"renderURL":    renderURL(r),
		"buildInitReq": buildInitReq,
		"fieldName":    fieldName(r),
		"tsUndefined": func(fieldType data.Type) string {
			return tsUndefined(r, fieldType)
		},
	})

	t = template.Must(t.Parse(tmpl))
	return t
}

func fieldName(r *registry.Registry) func(name string) string {
	return func(name string) string {
		if r.UseProtoNames {
			return name
		}

		return strcase.ToLowerCamel(name)
	}
}

func renderURL(r *registry.Registry) func(method data.Method) string {
	fieldNameFn := fieldName(r)
	return func(method data.Method) string {
		methodURL := method.URL
		reg := regexp.MustCompile("{([^}]+)}")
		matches := reg.FindAllStringSubmatch(methodURL, -1)
		fieldsInPath := make([]string, 0, len(matches))
		if len(matches) > 0 {
			log.Debugf("url matches %v", matches)
			for _, m := range matches {
				expToReplace := m[0]
				fieldName := fieldNameFn(m[1])
				part := fmt.Sprintf(`${req["%s"]}`, fieldName)
				methodURL = strings.ReplaceAll(methodURL, expToReplace, part)
				fieldsInPath = append(fieldsInPath, fmt.Sprintf(`"%s"`, fieldName))
			}
		}
		urlPathParams := fmt.Sprintf("[%s]", strings.Join(fieldsInPath, ", "))

		if !method.ClientStreaming && method.HTTPMethod == "GET" {
			// parse the url to check for query string
			parsedURL, err := url.Parse(methodURL)
			if err != nil {
				return methodURL
			}
			var buildQueryFn string
			if urlPathParams != "[]" {
				buildQueryFn = fmt.Sprintf("${fm.buildQuery(req, %s)}", urlPathParams)
			} else {
				buildQueryFn = "${fm.buildQuery(req)}"
			}

			// prepend "&" if query string is present otherwise prepend "?"
			// trim leading "&" if present before prepending it
			if parsedURL.RawQuery != "" {
				methodURL = strings.TrimRight(methodURL, "&") + "&" + buildQueryFn
			} else {
				methodURL += buildQueryFn
			}
		}

		return methodURL
	}
}

func buildInitReq(method data.Method) string {
	httpMethod := method.HTTPMethod
	m := `method: "` + httpMethod + `"`
	fields := []string{m}
	if method.HTTPRequestBody == nil || *method.HTTPRequestBody == "*" {
		fields = append(fields, "body: JSON.stringify(req, fm.replacer)")
	} else if *method.HTTPRequestBody != "" {
		fields = append(fields, `body: JSON.stringify(req["`+*method.HTTPRequestBody+`"], fm.replacer)`)
	}

	return strings.Join(fields, ", ")

}

// GetFetchModuleTemplate returns the go template for fetch module
func GetFetchModuleTemplate() *template.Template {
	t := template.New("fetch")
	return template.Must(t.Parse(fetchTmpl))
}

// include is the include template functions copied from
// copied from: https://github.com/helm/helm/blob/8648ccf5d35d682dcd5f7a9c2082f0aaf071e817/pkg/engine/engine.go#L147-L154
func include(t *template.Template) func(name string, data interface{}) (string, error) {
	return func(name string, data interface{}) (string, error) {
		buf := bytes.NewBufferString("")
		if err := t.ExecuteTemplate(buf, name, data); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
}

// check undefined
func tsUndefined(r *registry.Registry, fieldType data.Type) string {
	if fieldType.GetType().IsOneOfField {
		return "?"
	}
	return ""
}

func tsType(r *registry.Registry, fieldType data.Type) string {
	info := fieldType.GetType()
	typeInfo, ok := r.Types[info.Type]
	if ok && typeInfo.IsMapEntry {
		keyType := tsType(r, typeInfo.KeyType)
		valueType := tsType(r, typeInfo.ValueType)

		return fmt.Sprintf("{[key: %s]: %s}", keyType, valueType)
	}

	typeStr := ""
	if strings.Index(info.Type, ".") != 0 {
		typeStr = mapScalaType(info.Type)
	} else if !info.IsExternal {
		typeStr = typeInfo.PackageIdentifier
	} else {
		typeStr = mapGoogleType(data.GetModuleName(typeInfo.Package, typeInfo.File) + "." + typeInfo.PackageIdentifier)
	}

	if info.IsRepeated {
		typeStr += "[]"
	}

	if info.IsOptional || info.IsOneOfField {
		typeStr += " | null"
	}

	return typeStr
}

func mapScalaType(protoType string) string {
	switch protoType {
	case "uint64", "sint64", "int64", "fixed64", "sfixed64", "string":
		return "string"
	case "float", "double", "int32", "sint32", "uint32", "fixed32", "sfixed32":
		return "number"
	case "bool":
		return "boolean"
	case "bytes":
		return "Uint8Array"
	}

	return ""

}

func mapGoogleType(protoType string) string {
	switch protoType {
	case
		"GoogleProtobufTimestamp.Timestamp",
		"GoogleProtobufWrappers.Int64Value",
		"GoogleProtobufWrappers.UInt64Value",
		"GoogleProtobufWrappers.StringValue",
		"GoogleProtobufWrappers.BytesValue":
		return "string"
	case
		"GoogleProtobufWrappers.DoubleValue",
		"GoogleProtobufWrappers.Int32Value",
		"GoogleProtobufWrappers.FloatValue",
		"GoogleProtobufWrappers.UInt32Value":
		return "number"
	case
		"GoogleProtobufWrappers.BoolValue":
		return "boolean"
	}

	return protoType
}
